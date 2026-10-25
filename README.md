# Employee Manager

An admin-only web app for creating, viewing, updating and deleting employee records.
Built with Flask and SQLite. The whole app is one file (`app.py`).

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. On first run an admin account is created and its random
password is printed once in the terminal. To choose your own credentials instead:

```bash
ADMIN_USERNAME=hr_admin ADMIN_PASSWORD='a-long-passphrase' python app.py
```

## Features

- Create, read (list, search, filter by department, paginate, detail page), update, delete
- Audit log of logins and every create / update / delete (`/audit`)

## Security

| Concern | How it is handled |
|---|---|
| Authentication | Every page except `/login` requires an admin session |
| Passwords | Stored as salted hashes (Werkzeug), never in plain text |
| Brute force | Account locks for 15 minutes after 5 failed logins; generic error message |
| Sessions | HttpOnly, SameSite=Lax cookie, 30-minute idle timeout, session reset on login |
| CSRF | Per-session token required on every POST (including logout and delete) |
| SQL injection | Parameterized queries only |
| XSS | Jinja auto-escaping on all output, plus a Content-Security-Policy header |
| Clickjacking / sniffing | `X-Frame-Options`, `X-Content-Type-Options`, `no-store` caching |

## Validation (server-side; browser checks are only a convenience)

- Names: 1-50 letters (spaces, `-`, `'`, `.` allowed)
- Email: valid format, lowercased, unique
- Phone: optional, 7-15 digits
- Department: must be one of the configured list; Status: Active / Inactive
- Position: 2-80 characters from a safe set
- Salary: number from 0 to 10,000,000 with at most 2 decimals
- Hire date: valid `YYYY-MM-DD`, not in the future

## Before using real data

- Serve over HTTPS and set `FORCE_HTTPS=1` so the session cookie is marked Secure
- Set a fixed `SECRET_KEY` environment variable (otherwise sessions reset on restart)
- Run behind a production server such as `gunicorn app:app`, not the built-in one
- Encrypt the database file at rest (disk encryption or SQLCipher) and back it up
- For multiple admins, roles, or MFA, extend the `admins` table; the current app has
  no UI for adding admins
