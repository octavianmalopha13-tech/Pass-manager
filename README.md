# pass-manager

A small, offline, encrypted password manager written in Rust.

Single binary. One encrypted file. No daemon, no network, no cloud.

## Design

- **Key derivation:** Argon2id (19 MiB / 2 iterations / 1 lane), fresh random
  16-byte salt per save. The parameters are stored *in the vault header*, so
  future increases don't orphan existing vaults.
- **Encryption:** AES-256-GCM with a fresh 12-byte nonce per save. The
  ciphertext is authenticated, so a wrong password or a tampered file fails
  cleanly rather than decrypting to garbage.
- **Header format:** 48 bytes — `PWMGRv01` magic, salt, Argon2 params, nonce.
  Versioned so the format can evolve without breaking existing vaults.
- **Atomic writes:** saves go to a `.tmp` sibling and are `rename(2)`d into
  place — a crash mid-write never truncates the vault.
- **Backups:** the previous vault is copied to `vault.enc.bak` before each save.
- **Permissions:** the vault is forced to `0600` on write, regardless of the
  process umask.
- **Memory hygiene:** the master password, derived key, and decrypted JSON
  plaintext are zeroized on drop (`zeroize` crate).

## Usage

```sh
# Create a vault (default path: vault.enc)
pass-manager init

# Add an entry
pass-manager add --site github --user alice --password 'hunter2' --notes '2FA on'

# Retrieve
pass-manager get --site github
pass-manager get --site github --copy   # copy password to clipboard

# List, update, delete
pass-manager list
pass-manager update --site github --password 'newpass'
pass-manager delete --site github

# Generate a random password
pass-manager gen --length 24
pass-manager gen --length 24 --no-symbols

# Pipe a generated password straight into a new entry
pass-manager gen --length 32 \
  | pass-manager add --site bank --user alice --password-stdin
## Related

- [`Vault-tui`](https://github.com/octavianmalopha13-tech/Vault-tui) — a terminal UI for the same vault format.
