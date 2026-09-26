use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use vault_core::{
    check_vault_header, load_vault, save_vault, Entry, Vault, VaultError,
};

// ---- CLI-specific error mapping ----
// vault-core doesn't know about clipboards or stdin, so those two helpers
// return io::Result and we convert at the call site.

fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("termux-clipboard-set")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| std::io::Error::other("failed to open stdin"))?
        .write_all(text.as_bytes())?;

    let status = child.wait()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "termux-clipboard-set exited with {} (is the Termux:API app installed?)",
            status
        )));
    }
    Ok(())
}

fn read_stdin_password() -> std::io::Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;

    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    if s.is_empty() {
        return Err(std::io::Error::other("no password on stdin"));
    }
    Ok(s)
}

fn cmd_rotate(vault_path: &str) -> vault_core::Result<()> {
    check_vault_header(vault_path)?;

    // 1. Load with the current password. Fails fast if wrong — we don't want
    //    to prompt for a new password if the user can't prove the old one.
    let old = Zeroizing::new(rpassword::prompt_password("Current master password: ")?);
    let vault = load_vault(vault_path, &old)?;

    // 2. New password, twice.
    let new1 = Zeroizing::new(rpassword::prompt_password("New master password: ")?);
    let new2 = Zeroizing::new(rpassword::prompt_password("Confirm new master password: ")?);

    if *new1 != *new2 {
        eprintln!("Passwords do not match");
        std::process::exit(1);
    }

    if *old == *new1 {
        eprintln!("New password is the same as the old one");
        std::process::exit(1);
    }

    // 3. Re-save with the new password. save_vault generates a fresh salt,
    //    derives a new key, encrypts, and writes atomically. The old vault
    //    is copied to vault.enc.bak first, so nothing is lost on failure.
    save_vault(vault_path, &vault, &new1)?;

    println!("Master password rotated.");
    println!("Old vault (encrypted with the old password) is at {}.bak", vault_path);
    Ok(())
}


// ---- CLI definition ----

#[derive(Parser)]
#[command(name = "pass-manager")]
#[command(about = "A secure password manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "vault.enc")]
    vault: String,
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
    /// Change the master password of an existing vault
    Rotate,
}

// ---- main + run ----

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(e.exit_code());
    }
}

fn run() -> vault_core::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if std::path::Path::new(&cli.vault).exists() {
                eprintln!("Refusing to overwrite existing {}", cli.vault);
                std::process::exit(1);
            }
            let password = rpassword::prompt_password("Master password: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;
            if password != confirm {
                eprintln!("Passwords do not match");
                std::process::exit(1);
            }
            save_vault(&cli.vault, &Vault::default(), &password)?;
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

            if vault.find(&site).is_some() {
                eprintln!("Entry '{}' already exists", site);
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

            match vault.find(&site) {
                Some(e) => {
                    if copy {
                        copy_to_clipboard(&e.password)?;
                        println!("Copied password for '{}' to clipboard", site);
                    } else {
                        println!("site:     {}", e.site);
                        println!("user:     {}", e.user);
                        println!("password: {}", e.password);
                        println!("notes:    {}", e.notes);
                    }
                }
                None => return Err(VaultError::NoEntry(site)),
            }
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

            vault.remove(&site)?;
            save_vault(&cli.vault, &vault, &master)?;
            println!("Deleted");
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

            match vault.find_mut(&site) {
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
                    println!("Updated");
                }
                None => return Err(VaultError::NoEntry(site)),
            }
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

        //Commands::Rotate => cmd_rotate(&cli.vault)?,       

            let mut rng = rand::thread_rng();
            let pw: String = (0..length)
                .map(|_| pool[rng.gen_range(0..pool.len())] as char)
                .collect();

            println!("{}", pw);
        }
     
        Commands::Rotate => cmd_rotate(&cli.vault)?,
    }

    Ok(())
}
