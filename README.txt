SecureShare - Flask encrypted file-sharing project
===================================================

Quick start (Linux)
-------------------
1. Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate

2. Install packages:
   pip install -r requirements.txt

3. Create .env from .env.example and generate secrets:
   cp .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"

   Put the first value in FLASK_SECRET_KEY and the second in MASTER_KEY.

4. Run:
   python app.py

5. Open http://127.0.0.1:5000

Security design
---------------
- Each uploaded file receives a fresh random 256-bit AES-GCM key and 96-bit nonce.
- The file is encrypted before writing ciphertext to storage/encrypted.
- The per-file key is wrapped using a server master key (AES-GCM).
- Account passwords and share passwords are stored as Werkzeug password hashes.
- Share tokens are generated using Python's cryptographically secure secrets module.
- Share access checks enforce password, expiry, revocation and download permission.
- POST requests use a session-bound CSRF token.
- Basic security response headers are set.

Important limitations
---------------------
This is an educational local MVP, not a production-ready internet service.
The application server decrypts a file when an authorized download is requested;
therefore this is encrypted-at-rest, not zero-knowledge end-to-end encryption.
For production, add HTTPS, rate limiting, malware scanning, email verification,
stronger audit retention, key rotation, secure backups, external key management,
background expiry cleanup, and deployment hardening. Do not expose Flask's
development server directly to the public internet.

Master-key warning
------------------
The MASTER_KEY is essential. If it is lost, files cannot be decrypted. If it is
stolen, an attacker with the database and ciphertext may be able to recover files.
Keep .env out of version control and maintain a secure backup of the key.
Changing MASTER_KEY without rewrapping stored keys will make old files unreadable.

Demo checklist
--------------
1. Register a user and log in.
2. Upload a small PDF or TXT file.
3. Inspect storage/encrypted: the stored .bin file should not resemble the original.
4. Download from the owner's dashboard and compare with the original.
5. Create a share link with a password and 1-day expiry.
6. Open the link in a private browser window; try a wrong password, then the correct one.
7. Disable downloads on another link and verify that download is blocked.
8. Revoke a link and verify it no longer works.
9. Open Activity and review recorded events.
