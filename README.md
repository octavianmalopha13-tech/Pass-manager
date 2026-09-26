# pass-manager

An offline, encrypted password manager. Single binary, one encrypted file.

## Design

- **Key derivation:** Argon2id (19 MiB / 2 iterations / 1 lane), fresh random
  16-byte salt per save. Parameters live in the vault header, so future
  increases don't orphan existing vaults.
- **Encryption:** AES-256-GCM with a fresh 12-byte nonce per save.
- **Header format:** 48 bytes — `PWMGRv01` magic, salt, Argon2 params, nonce.
- **Atomic writes:** saves go to a `.tmp` sibling and are `rename(2)`d into place.
- **Backups:** the previous vault is copied to `vault.enc.bak` before each save.
- **Permissions:** `0600` enforced on write, regardless of umask.
- **Memory hygiene:** secrets are zeroized on drop.

## Usage

    pass-manager -v vault.enc init
    pass-manager -v vault.enc add --site github --user alice
    pass-manager -v vault.enc get --site github --copy
    pass-manager -v vault.enc list
    pass-manager -v vault.enc delete --site github
    pass-manager gen --length 24
    pass-manager -v vault.enc rotate

## Exit codes

    0  success
    1  user error (wrong password, missing entry)
    2  data error (corrupt vault, bad magic)
    3  internal error (KDF or cipher failure)

## Rotating the master password

`rotate` decrypts with the current password and re-encrypts with the new one.
The old vault is preserved at `vault.enc.bak`.

**Sync note:** if you use `vault-sync`, rotate on one device then re-pull on
the others. Don't rotate while another device has unsaved changes.

## Related

- [vault-core](https://github.com/octavianmalopha13-tech/vault-core) — shared library
- [Vault-tui](https://github.com/octavianmalopha13-tech/Vault-tui) — terminal UI
- [vault-api](https://github.com/octavianmalopha13-tech/vault-api) — HTTP API
- [vault-sync](https://github.com/octavianmalopha13-tech/vault-sync) — sync

## License

MIT
