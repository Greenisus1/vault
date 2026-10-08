# VAULT

An encrypted local signing-key store for custom app login. Version 1.1.0.

This is **not WebAuthn, website passkeys, or your device login password**. It uses a separate VAULT password. It does not log into existing apps automatically: each app must integrate the SDK and securely enroll its public key. The included demo logs into a local example, not any real account. Existing cview/keys2.py is not modified or imported.

## Use

Python 3, python3-cryptography, an interactive terminal and a writable home folder are needed. Optional GUI needs python3-tk and desktop/VNC.

    bash app-store.sh install
    bash app-store.sh run

The reviewed install hook prints before installing missing Tk or cryptography with apt-get, only if root and apt-get are available. Otherwise it stops with instructions. It does not install a desktop, change device passwords, add services or modify app logins. Missing or inaccessible DISPLAY gets a desktop/VNC message.

Create a separate VAULT password of at least 12 characters in the local terminal or optional window. Unlock, create an app key, enroll the displayed PUBLIC key in the app's trusted registration process, and approve each login request. The GUI currently provides registration and an isolated demo; real apps integrate vault_core.py. No background login broker or browser integration is included. Do not send passwords or private keys in chat.

The store is ~/.local/share/vault/keys.json. Its folder must be mode 700, its file mode 600, owned by the current user. Running as root creates a root-owned vault, not one shared with your desktop user. Idle lock is after 2 minutes; Lock now and window close release in-memory references. There is no auto-unlock from environment variables, device-password bypass, password export or clipboard flow.

## App integration

`KeyStore` provides create/unlock/lock, register(app_id), public_key(app_id), and sign_login(request, approved_app_id). App IDs use lowercase letters, digits, dot, dash and underscore. Different app IDs get different Ed25519 keypairs. Private keys remain in the vault; login returns a signature, not a key or saved password.

`AppVerifier` is a reference **in-memory, single-user demo verifier**, not a production identity server. Enroll a trusted public key, call challenge(), show the user the app and login action, then call sign_login only after approval. verify() validates the signature against the stored public key and consumes the nonce. It rejects expired or replayed responses. Challenges last 60 seconds and bind app ID, action, nonce and expiry.

Production apps must authenticate initial enrollment, bind the public key to the correct user, keep pending challenges server-side, atomically consume them, use authenticated transport, maintain sessions and provide account recovery. Do not accept a new public key supplied in a login response. Do not silently replace enrolled keys. The SDK does not authenticate a caller's claimed app ID: a malicious program under the same user can impersonate an app. The user-facing prompt and app-specific binding are not OS-level caller isolation. Protect login code, public-key bindings and vault files.

    python3 demo_login.py
    python3 -m unittest -v
    python3 vault.py --version

The terminal demo uses a temporary encrypted vault and asks for a test-only password. It proves create/register/lock/unlock/login/replay rejection, then removes the temporary files. The GUI's Test demo login uses a vault-demo key in the user's chosen vault.

## Security and limits

- cryptography's Fernet authenticated encryption protects the entire app-key map at rest. scrypt derives a key using a random 16-byte salt (N=32768, r=8, p=1). No custom cipher. Ed25519 uses the cryptography library.
- Atomic replacement and an exact-byte stale-file check reduce accidental concurrent edits. There is no cross-process transaction lock: do not use multiple VAULT writers at once. Creation refuses to overwrite. Symlink paths are refused, but this is not protection from root or a malicious same-user process racing filesystem changes.
- Maximum 200 app keys, vault input 1 MiB, challenge queue 100. No network, telemetry, secret logs or credential import.
- This is a prototype, not security-audited software. Python cannot promise memory zeroing, protection from root/same-user malware, or hardware-backed keys. A weak password permits offline guessing. It is not a hardware authenticator.
- Forgotten VAULT password has no reset that restores keys. Back up the encrypted file securely before relying on keys for real accounts. The backup needs the same password; losing or changing keys can lock you out of apps. No migration, deletion, key rotation or production recovery workflow is included in this version.
- Linux tests and a Tk virtual-display preview were checked. Physical Pi, non-Linux systems and real app/account integration are untested.

## References

https://cryptography.io/en/latest/fernet/
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
https://github.com/duo-labs/py_webauthn

App Store marker/version included. Publication requires its own approval.

## Terminal update (1.1.0)

Terminal mode is now the default, works over interactive SSH and needs no Tk or desktop:

    python3 vault.py
    bash app-store.sh run

Colored block/box header and highlighted arrow-key menu (j/k also work), Esc/q returns. Full create/unlock/lock, create/list app keys and local demo-login flow. Passwords are masked and entered locally, never stored in environment variables or logged. Lock is enforced on the next operation after two minutes idle; terminal may still display the last menu until the next key. No private keys are displayed. Public-key output may remain in your terminal scrollback. UI filters control characters before rendering. Use Unicode monospace terminal, 80x24 recommended; no TTY gives a clear error. Plain noninteractive input is unsupported, rather than prompting secrets through a pipeline.

Optional desktop window: python3 vault.py --gui or bash app-store.sh gui. Terminal install checks only cryptography; gui additionally checks Tk and display. Missing dependencies can be installed by reviewed hook only root+apt, with a printed notice. No desktop is installed. Security, recovery and SDK limits above are unchanged. Current version is 1.1.0; terminal PTY capture plus scripted full-flow test checked, physical Pi untested.
