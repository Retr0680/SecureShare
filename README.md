# SecureShare

SecureShare is an educational Flask web application for encrypted file storage and controlled file sharing.

## Features

- User registration and login with Werkzeug password hashing.
- AES-256-GCM encryption before files are written to local storage.
- A fresh random data-encryption key per file; the key is wrapped using a server-side master key.
- Password-protected sharing links, expiry, manual revocation, and download permission.
- Session-bound CSRF protection on POST requests.
- Basic security response headers and lightweight per-process throttling for login/share unlock.
- Activity records for important file and share events.

## Requirements

- Python 3.10+
- pip

## Local setup (Linux/macOS)

```bash
git clone https://github.com/Retr0680/SecureShare.git
cd SecureShare
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Generate independent secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Put the first value in `FLASK_SECRET_KEY` and the second in `MASTER_KEY` in `.env`. Do not commit `.env`.

Start the app:

```bash
python app.py
```

Open http://127.0.0.1:5000.

## Windows setup

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Generate the two secrets using the Python commands above and edit `.env`.

## Demo workflow

1. Register and log in.
2. Upload a small PDF or text file.
3. Download it from the owner dashboard and compare it with the original.
4. Create a share with a password and expiry.
5. Open the link in a private/incognito window.
6. Try a wrong password, then the correct password.
7. Verify that download permission can be disabled.
8. Revoke a link and verify that it can no longer be opened.
9. Review the Activity page.

## Security notes and limitations

This MVP provides encryption at rest, not zero-knowledge end-to-end encryption: the server decrypts a file during an authorized download. The master key is essential; losing it makes stored files unrecoverable. Back it up securely and never commit it.

The built-in throttling is in-memory and per process, suitable only for a local educational demo. A multi-worker deployment needs a shared rate-limit store. Production deployment also requires HTTPS, a production WSGI server, secure secret management, rate limiting at the edge, malware scanning, key rotation, backups, monitoring, and deployment hardening. Do not expose Flask's development server directly to the public internet.

## Data handling

The SQLite database and encrypted file payloads are local runtime data and are intentionally excluded from version control. They are created automatically when the app starts and a user uploads a file.
