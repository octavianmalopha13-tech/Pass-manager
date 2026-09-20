use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
//use std::string::String;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use rand::RngCore;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"PWMGRv01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 8 + SALT_LEN + 4 + 4 + 4 + NONCE_LEN; // 48

// Params for *new* vaults. Bump these freely; old vaults still read.
const ARGON2_M_COST: u32 = 19 * 1024; // KiB
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

#[derive(thiserror::Error, Debug)]
enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a pass-manager vault (magic: {0})")]
    BadMagic(String),

    #[error("vault file too short ({0} bytes, need at least {1})")]
    TooShort(usize, usize),

    #[error("bad argon2 params: {0}")]
    BadParams(String),

    #[error("argon2: {0}")]
    Kdf(String),

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed (wrong password or corrupted vault)")]
    Decrypt,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("clipboard: {0}")]
    Clipboard(String),

    #[error("no password on stdin")]
    NoStdinPassword,

    #[error("no entry for '{0}'")]
    NoEntry(String),
}

impl VaultError {
    /// POSIX-style exit codes: 0 = ok, 1 = user error, 2 = data error, 3 = internal.
    fn exit_code(&self) -> i32 {
        match self {
            VaultError::Decrypt
            | VaultError::NoStdinPassword
            | VaultError::Clipboard(_)
            | VaultError::NoEntry(_) => 1,
            VaultError::Io(_)
            | VaultError::BadMagic(_)
            | VaultError::TooShort(_, _)
            | VaultError::Json(_) => 2,
            VaultError::BadParams(_) | VaultError::Kdf(_) | VaultError::Encrypt => 3,
            // VaultError::Decrypt
            //| VaultError::NoStdinPassword
            //| VaultError::Clipboard(_)
            //| VaultError::NoEntry(_) => 1,
        }
    }
}

type Result<T> = std::result::Result<T, VaultError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Entry {
    site: String,
    user: String,
    password: String,
    notes: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Vault {
    entries: Vec<Entry>,
}

#[derive(Parser)]
#[command(name = "pass-manager")]
#[command(about = "A secure password manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "vault.enc")]
    vault: String,
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("termux-clipboard-set")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VaultError::Clipboard(format!("cannot run termux-clipboard-set: {}", e)))?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| VaultError::Clipboard("failed to open stdin".into()))?
        .write_all(text.as_bytes())?; // io::Error → From → VaultError::Io

    let status = child.wait()?;

    if !status.success() {
        return Err(VaultError::Clipboard(format!(
            "termux-clipboard-set exited with status {} (is the Termux:API app installed?)",
            status
        )));
    }
    Ok(())
}

fn read_stdin_password() -> Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?; // io::Error → VaultError::Io

    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    if s.is_empty() {
        return Err(VaultError::NoStdinPassword);
    }
    Ok(s)
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| VaultError::BadParams(e.to_string()))?;
    let instance = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt_b64 = STANDARD_NO_PAD.encode(salt);
    let salt_string =
        SaltString::from_b64(&salt_b64).map_err(|e| VaultError::Kdf(e.to_string()))?;

    let hash = instance
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;

    let binding = hash.hash.unwrap();
    let hash_bytes = binding.as_bytes();
    let key_slice: &[u8; 32] = hash_bytes[..32]
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| VaultError::Kdf(e.to_string()))?;
    Ok(Zeroizing::new(*key_slice))
}

fn encrypt_payload(vault: &Vault, key: &[u8; 32]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut plaintext = serde_json::to_vec(vault)?; // Json via #[from]

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| VaultError::Encrypt)?;

    plaintext.zeroize();
    Ok((ciphertext, nonce_bytes))
}

fn decrypt_payload(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8; 32]) -> Result<Vault> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Decrypt)?; // collapsed — GCM failure = wrong pw or corrupt

    let vault = serde_json::from_slice(&plaintext)?; // Json via #[from]
    plaintext.zeroize();
    Ok(vault)
}

fn check_vault_header(path: &str) -> Result<()> {
    let blob = fs::read(path)?;
    if blob.len() < HEADER_LEN {
        return Err(VaultError::TooShort(blob.len(), HEADER_LEN));
    }
    if &blob[..8] != MAGIC {
        let magic = String::from_utf8_lossy(&blob[..8]).into_owned();
        //magic.copy_from_slice(&blob[..8]);
        return Err(VaultError::BadMagic(magic));
    }
    Ok(())
}

fn load_vault(path: &str, password: &str) -> Result<Vault> {
    let blob = fs::read(path)?; // Io via #[from]
    check_vault_header(path)?;

    let salt = &blob[8..24];
    let m_cost = u32::from_le_bytes(blob[24..28].try_into().unwrap());
    let t_cost = u32::from_le_bytes(blob[28..32].try_into().unwrap());
    let p_cost = u32::from_le_bytes(blob[32..36].try_into().unwrap());
    let nonce = &blob[36..48];
    let payload = &blob[48..];

    let key = derive_key(password, salt, m_cost, t_cost, p_cost)?;
    decrypt_payload(payload, nonce, &key)
}

fn save_vault(path: &str, vault: &Vault, password: &str) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let (ciphertext, nonce) = encrypt_payload(vault, &key)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
    out.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, &out)?; // Io via #[from]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;

    if Path::new(path).exists() {
        let _ = fs::copy(path, format!("{}.bak", path));
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        #[arg(long)]
        site: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value = "")]
        notes: String,
    },
    Get {
        #[arg(long)]
        site: String,
        #[arg(long)]
        copy: bool,
    },
    List,
    Delete {
        #[arg(long)]
        site: String,
    },
    Update {
        #[arg(long)]
        site: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    Gen {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(e.exit_code());
    }
}

//let salt=b"fixed-test-salt-16bytes!!!";
// use rand::RngCore;
//let mut salt = [0u8; 16];
//rand::thread_rng().fill_bytes(&mut salt);
// store `salt` next to the encrypted vault
//let key1=derive_key("hunter2",&salt).unwrap();
//let key2=derive_key("hunter2",&salt).unwrap();
//let key3=derive_key("hunter3",&salt).unwrap();

//println!("key1:{:?}",key1);
//println!("key2:{:?}",key2);
//println!("key3:{:?}",key3);
//println!("key1==key2:{}",key1==key2);
//println!("key1==key3:{}",key1==key3);

//return;
fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if std::path::Path::new(&cli.vault).exists() {
                eprintln!("Refusing to overwrite existing {}", cli.vault);
                std::process::exit(1);
            }
            // let mut salt=[0u8;16];
            // rand::thread_rng().fill_bytes(&mut salt);
            let password = rpassword::prompt_password("Master password: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;
            if password != confirm {
                eprintln!("Passwords do not match");
                std::process::exit(1);
            }

            save_vault(&cli.vault, &Vault::default(), &password)?;
            //let key=derive_key(&password,&salt)?;
            //let vault=Vault::default();
            println!("Initialized {}", cli.vault);
        }
        Commands::Add {
            site,
            user,
            password,
            password_stdin,
            notes,
        } => {
            let entry_pw = match (password, password_stdin) {
                (Some(_), true) => {
                    eprintln!("Use either --password or --password-stdin, not both");
                    std::process::exit(1);
                }
                (Some(p), false) => p,
                (None, true) => read_stdin_password()?,
                (None, false) => rpassword::prompt_password("Entry password: ")?,
            };

            check_vault_header(&cli.vault)?;
            let master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let mut vault = load_vault(&cli.vault, &master)?;
            if vault.entries.iter().any(|e| e.site == site) {
                eprintln!("Entry '{}'already exists", site);
                std::process::exit(1);
            }
            vault.entries.push(Entry {
                site,
                user,
                password: entry_pw,
                notes,
            });
            save_vault(&cli.vault, &vault, &master)?;
            println!("Added!");
        }
        Commands::Get { site, copy } => {
            check_vault_header(&cli.vault)?;
            let master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let vault = load_vault(&cli.vault, &master)?;
            match vault.entries.iter().find(|e| e.site == site) {
                Some(e) => {
                    if copy {
                        copy_to_clipboard(&e.password)?;
                        println!("Copied password for '{}' to clipboard", site);
                    } else {
                        println!("site:  {}", e.site);
                        println!("user:  {}", e.user);
                        println!("password:  {}", e.password);
                        println!("notes:  {}", e.notes);
                    }
                }
                None => return Err(VaultError::NoEntry(site)),
                //None=>eprintln!("No entry for `{}`",site),
            }
            // lprintln!("TODO: get {}",site);
        }
        Commands::List => {
            check_vault_header(&cli.vault)?;
            let master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let vault = load_vault(&cli.vault, &master)?;
            if vault.entries.is_empty() {
                println!("(empty vault)");
            }
            for e in &vault.entries {
                println!("{} ({})", e.site, e.user);
            }
        }
        Commands::Delete { site } => {
            check_vault_header(&cli.vault)?;
            let master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let mut vault = load_vault(&cli.vault, &master)?;
            let before = vault.entries.len();
            vault.entries.retain(|e| e.site != site);
            if vault.entries.len() == before {
                return Err(VaultError::NoEntry(site));
                // eprintln!("No entry for '{}'",site);
            } else {
                save_vault(&cli.vault, &vault, &master)?;
                println!("Deleted");
            }
            //println!("TODO: delete {}", site);
        }
        Commands::Update {
            site,
            user,
            password,
            notes,
        } => {
            check_vault_header(&cli.vault)?;
            let master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let mut vault = load_vault(&cli.vault, &master)?;
            match vault.entries.iter_mut().find(|e| e.site == site) {
                Some(e) => {
                    if let Some(u) = user {
                        e.user = u;
                    }
                    if let Some(p) = password {
                        e.password = p;
                    }
                    if let Some(n) = notes {
                        e.notes = n;
                    }

                    save_vault(&cli.vault, &vault, &master)?;
                    println!("Updated")
                }

                None => return Err(VaultError::NoEntry(site)),
                //None=>eprintln!("No entry for '{}'",site),
            }
            //println!("TODO: update {}(user: {:?}),password: {:?},notes:{:?}",site,user,password,notes);
        }
        Commands::Gen { length, no_symbols } => {
            use rand::Rng;
            const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const DIGITS: &[u8] = b"0123456789";
            const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";

            let mut pool: Vec<u8> = Vec::new();
            pool.extend_from_slice(LETTERS);
            pool.extend_from_slice(DIGITS);
            if !no_symbols {
                pool.extend_from_slice(SYMBOLS);
            }

            let mut rng = rand::thread_rng();
            let pw: String = (0..length)
                .map(|_| pool[rng.gen_range(0..pool.len())] as char)
                .collect();

            println!("{}", pw);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "test-master-password";
    // Use lower cost for tests so they run fast — this is unrelated to vault security,
    // the test just checks round-trip correctness, not KDF strength.
    const TEST_M_COST: u32 = 8 * 1024;
    const TEST_T_COST: u32 = 1;
    const TEST_P_COST: u32 = 1;

    fn test_salt() -> [u8; SALT_LEN] {
        [7u8; SALT_LEN]
    }

    fn sample_vault() -> Vault {
        Vault {
            entries: vec![
                Entry {
                    site: "github".into(),
                    user: "alice".into(),
                    password: "p@ss".into(),
                    notes: "2FA on".into(),
                },
                Entry {
                    site: "email".into(),
                    user: "bob".into(),
                    password: "hunter2".into(),
                    notes: String::new(),
                },
            ],
        }
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = test_salt();
        let k1 = derive_key(PW, &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let k2 = derive_key(PW, &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn different_password_gives_different_key() {
        let salt = test_salt();
        let k1 = derive_key(PW, &salt, TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let k2 = derive_key(
            "other-password",
            &salt,
            TEST_M_COST,
            TEST_T_COST,
            TEST_P_COST,
        )
        .unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn different_salt_gives_different_key() {
        let k1 = derive_key(PW, &[1u8; 16], TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let k2 = derive_key(PW, &[2u8; 16], TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn payload_round_trip() {
        let key = derive_key(PW, &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let vault = sample_vault();

        let (ciphertext, nonce) = encrypt_payload(&vault, &key).unwrap();
        let recovered = decrypt_payload(&ciphertext, &nonce, &key).unwrap();

        assert_eq!(recovered.entries.len(), 2);
        assert_eq!(recovered.entries[0].site, "github");
        assert_eq!(recovered.entries[0].password, "p@ss");
        assert_eq!(recovered.entries[1].site, "email");
        assert_eq!(recovered.entries[1].notes, "");
    }

    #[test]
    fn wrong_password_decryption_fails() {
        let key_good = derive_key(PW, &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let key_bad =
            derive_key("wrong", &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();

        let (ciphertext, nonce) = encrypt_payload(&sample_vault(), &key_good).unwrap();
        let result = decrypt_payload(&ciphertext, &nonce, &key_bad);

        assert!(matches!(result, Err(VaultError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_key(PW, &test_salt(), TEST_M_COST, TEST_T_COST, TEST_P_COST).unwrap();
        let (mut ciphertext, nonce) = encrypt_payload(&sample_vault(), &key).unwrap();

        // flip a bit in the middle of the ciphertext
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0x01;

        let result = decrypt_payload(&ciphertext, &nonce, &key);
        assert!(matches!(result, Err(VaultError::Decrypt)));
    }

    // ---- File-level round trip using a temp path ----

    fn temp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("pass-manager-test-{}-{}", name, std::process::id()));
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn save_load_round_trip() {
        let path = temp_path("roundtrip");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}.bak", path));
        let _ = fs::remove_file(format!("{}.tmp", path));

        // save_vault uses the production ARGON2 params — a bit slow but proves
        // the real path works end-to-end. If too slow, temporarily parameterize.
        save_vault(&path, &sample_vault(), PW).unwrap();

        // file has the magic
        let blob = fs::read(&path).unwrap();
        assert_eq!(&blob[..8], MAGIC);

        let loaded = load_vault(&path, PW).unwrap();
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].site, "github");

        // wrong password on the same file fails cleanly
        let err = load_vault(&path, "wrong").unwrap_err();
        assert!(matches!(err, VaultError::Decrypt));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}.bak", path));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let path = temp_path("badmagic");
        fs::write(
            &path,
            b"XXXXXXXXYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
        )
        .unwrap();
        let err = load_vault(&path, PW).unwrap_err();
        match err {
            VaultError::BadMagic(_) => {}
            other => panic!("expected BadMagic, got {:?}", other),
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn too_short_is_rejected() {
        let path = temp_path("short");
        fs::write(&path, b"PWMGRv01").unwrap(); // 8 bytes, magic ok, but no header
        let err = load_vault(&path, PW).unwrap_err();
        match err {
            VaultError::TooShort(n, min) => {
                assert_eq!(n, 8);
                assert_eq!(min, HEADER_LEN);
            }
            other => panic!("expected TooShort, got {:?}", other),
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn bad_argon2_params_rejected() {
        // 0 KiB memory is invalid
        let result = derive_key(PW, &test_salt(), 0, 1, 1);
        assert!(matches!(result, Err(VaultError::BadParams(_))));
    }

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(VaultError::Decrypt.exit_code(), 1);
        assert_eq!(VaultError::NoEntry("x".into()).exit_code(), 1);
        assert_eq!(VaultError::TooShort(0, 48).exit_code(), 2);
        assert_eq!(VaultError::BadMagic("x".into()).exit_code(), 2);
        assert_eq!(VaultError::Kdf("x".into()).exit_code(), 3);
    }
}
