# PasswordManager

A local, offline password manager with a Qt desktop GUI. Your vault is a single
encrypted file on your machine — nothing is ever sent over the network.

## Features

- Entries with title, username, password, URL and notes; instant search
- Password generator (random characters or word passphrases) with strength estimate
- Copy username/password to the clipboard; the clipboard is cleared after 20 seconds
- Auto-lock after 5 minutes of inactivity (`Ctrl+L` to lock manually)
- Encrypted export/import for backups (import merges by entry, newest wins)
- Change master password

## Install & run

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pwmanager                     # or: .venv/bin/python -m pwmanager
.venv/bin/pwmanager --vault ~/other.pmv # use a different vault file
```

The default vault lives at `~/.local/share/pwmanager/vault.pmv`. On first run
you are asked to choose a master password. **It cannot be recovered** — if you
forget it, the vault is lost. Keep an exported backup somewhere safe.

On Wayland, install `wl-clipboard` so the clipboard can be cleared while the
window is unfocused.

## Keyboard shortcuts

| Action | Shortcut |
| --- | --- |
| New entry | `Ctrl+N` |
| Edit entry | `Ctrl+E` / double-click |
| Delete entry | `Del` |
| Copy username / password | `Ctrl+B` / `Ctrl+C` |
| Search | `Ctrl+F` |
| Generate password | `Ctrl+G` |
| Lock | `Ctrl+L` |
| Quit | `Ctrl+Q` |

`Ctrl+C` copies the selected entry's password, except while the search box has
focus — there it copies the selected search text as usual.

## How your passwords are protected

All passwords are stored encrypted, along with usernames, URLs, notes and
titles. The vault file contains no readable text, only random-looking bytes.
Nothing is ever written to disk unencrypted.

The encryption itself is not the weak point. AES-256 cannot be brute-forced
with any foreseeable technology. An attacker who steals the vault file can
only guess your **master password**, so the vault is exactly as strong as that
password:

- Each guess costs about 0.5 s of CPU time and 128 MiB of RAM, because the key
  is derived with scrypt. This makes large-scale guessing on GPUs or dedicated
  hardware very expensive.
- A master password that is short, reused or a common phrase can still be
  cracked. Use a long, unique one, such as a generated passphrase of 6 or more
  words (Tools → Generate Password… → Passphrase, about 72 bits). That is
  out of reach of any realistic attacker.
- There is no backdoor and no recovery. If you forget the master password, not
  even you can decrypt the vault.

## Security design

- **Key derivation:** scrypt (N=2¹⁷, r=8, p=1, about 128 MiB) with a random
  16-byte salt per vault. The parameters are stored in the file header, so they
  can be raised later without breaking existing vaults.
- **Encryption:** AES-256-GCM with a fresh random nonce on every save. The file
  header (format version, KDF parameters, salt) is authenticated, so any
  tampering is detected and the vault refuses to open.
- **Storage:** atomic writes (temp file + `fsync` + rename), file mode `0600`.
- **Master password:** creating a vault warns you if it is under 8 characters.
- **Exports** are re-encrypted under a separate password with their own salt.
- Generated passwords use Python's `secrets` module.
- Copied secrets carry the `x-kde-passwordManagerHint` so clipboard managers
  that honour it keep them out of their history.

Limitations:

- Python can't reliably wipe secrets from memory, so decrypted entries live in
  process memory while the vault is unlocked. Locking drops all references to
  them. Malware running as your user could read them while the vault is open,
  as it could with any password manager.
- The file size reveals roughly how much data the vault holds. It does not
  reveal any of the contents.

## Development

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```
