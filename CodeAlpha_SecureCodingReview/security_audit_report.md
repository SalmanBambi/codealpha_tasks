# Security Code Audit Report
**Project:** User Management System (Python in Jupyter)  
**Auditor:** Salman Ali 
**Organization:** CodeAlpha Internship — Task 3  
**Date:** May 2026  
**Language Audited:** Python 3  
**Files Reviewed:** `vulnerable_app.IPYNB`  

---

## Executive Summary

A manual security code review was conducted on a Python-based user management application. The audit identified **10 critical or high-severity vulnerabilities** spanning SQL injection, command injection, insecure cryptography, hardcoded credentials, and more. All findings have been documented with their risk level, root cause, and a remediated code example in `secure_app.IPYNB`.

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 4 |
| Medium | 2 |
| **Total** | **10** |

---

## Vulnerability Findings

---

### VUL-01 — SQL Injection
**Severity:** CRITICAL  
**Location:** `login()` function  
**CWE:** CWE-89

**Vulnerable Code:**
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**Description:**  
User-controlled input is directly concatenated into the SQL query string. An attacker can manipulate the query by entering a payload such as `' OR '1'='1` as the username, bypassing authentication entirely or dumping the entire database.

**Attack Example:**
```
username: ' OR '1'='1' --
password: anything
→ Logs in as the first user in the database (often admin)
```

**Remediation:**
```python
# Use parameterized queries with ? placeholders
result = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hashed_password)
).fetchone()
```

---

### VUL-02 — Hardcoded Credentials & Secret Keys
**Severity:** CRITICAL  
**Location:** Module-level constants  
**CWE:** CWE-798

**Vulnerable Code:**
```python
DB_USER     = "admin"
DB_PASSWORD = "admin123"
SECRET_KEY  = "supersecretkey123"
```

**Description:**  
Credentials and secret keys are hardcoded directly in source code. Anyone with access to the repository (including version control history) can extract these values. If the repository is public, credentials are exposed immediately.

**Remediation:**
```python
import os
DB_USER     = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
SECRET_KEY  = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```
Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).

---

### VUL-03 — Command Injection
**Severity:** CRITICAL  
**Location:** `ping_host()` function  
**CWE:** CWE-78

**Vulnerable Code:**
```python
output = subprocess.call("ping -c 1 " + host, shell=True)
```

**Description:**  
The `host` parameter is unsanitized user input passed directly to a shell command with `shell=True`. An attacker can inject additional OS commands by entering: `8.8.8.8; rm -rf /` or `8.8.8.8 && cat /etc/passwd`.

**Attack Example:**
```
host = "8.8.8.8; cat /etc/passwd"
→ Executes: ping -c 1 8.8.8.8; cat /etc/passwd
```

**Remediation:**
```python
import re
ALLOWED = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

def ping_host(host: str):
    if not ALLOWED.match(host):
        raise ValueError("Invalid hostname.")
    result = subprocess.run(
        ["ping", "-c", "1", host],  # List form — no shell parsing
        capture_output=True, text=True, timeout=5, shell=False
    )
    return result.stdout
```

---

### VUL-04 — Insecure Deserialization (Pickle)
**Severity:** CRITICAL  
**Location:** `load_session()` function  
**CWE:** CWE-502

**Vulnerable Code:**
```python
import pickle
def load_session(session_data):
    return pickle.loads(session_data)
```

**Description:**  
`pickle.loads()` on untrusted data allows arbitrary code execution. An attacker who can control `session_data` can craft a malicious pickle payload that executes any Python code on the server when deserialized.

**Remediation:**
```python
import json

def load_session(session_data: str) -> dict:
    try:
        data = json.loads(session_data)
        if not isinstance(data, dict):
            raise ValueError("Invalid session format.")
        return data
    except (json.JSONDecodeError, ValueError):
        return {}
```
Never use `pickle` for data that crosses a trust boundary. Use `json` or `msgpack` instead.

---

### VUL-05 — Weak Password Hashing (MD5)
**Severity:** HIGH  
**Location:** `hash_password()` function  
**CWE:** CWE-916

**Vulnerable Code:**
```python
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

**Description:**  
MD5 is cryptographically broken. It is extremely fast (billions of hashes per second on a GPU), has no salt, and is trivially crackable using rainbow tables or brute force. Stolen MD5 password hashes can be reversed within seconds.

**Remediation:**
```python
def hash_password(password: str) -> str:
    salt = os.environ.get("PASSWORD_SALT", "unique_app_salt")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=260000   # NIST recommended iteration count
    ).hex()
```
For production, use `bcrypt` or `argon2` which are purpose-built for password hashing.

---

### VUL-06 — Path Traversal
**Severity:** HIGH  
**Location:** `read_user_file()` function  
**CWE:** CWE-22

**Vulnerable Code:**
```python
def read_user_file(filename):
    base_dir = "/var/app/uploads/"
    filepath = base_dir + filename  # No sanitization
    with open(filepath, "r") as f:
        return f.read()
```

**Description:**  
An attacker can supply `../../etc/passwd` as the filename, causing the app to read sensitive system files outside the intended directory.

**Attack Example:**
```
filename = "../../etc/passwd"
→ Reads: /var/app/uploads/../../etc/passwd → /etc/passwd
```

**Remediation:**
```python
def read_user_file(filename: str) -> str:
    base_dir = os.path.abspath("/var/app/uploads/")
    safe_path = os.path.abspath(os.path.join(base_dir, os.path.basename(filename)))
    if not safe_path.startswith(base_dir):
        raise PermissionError("Path traversal detected.")
    with open(safe_path, "r") as f:
        return f.read()
```

---

### VUL-07 — Insecure Random Number Generation
**Severity:** HIGH  
**Location:** `generate_token()` function  
**CWE:** CWE-338

**Vulnerable Code:**
```python
def generate_token():
    return str(random.randint(100000, 999999))
```

**Description:**  
Python's `random` module is a pseudo-random number generator (PRNG) not suitable for security purposes. It produces predictable outputs and the token space (900,000 possible values) is trivially brute-forceable.

**Remediation:**
```python
import secrets

def generate_token() -> str:
    return secrets.token_hex(32)  # 256-bit cryptographically secure token
```

---

### VUL-08 — Sensitive Data in Logs
**Severity:** HIGH  
**Location:** `register_user()` function  
**CWE:** CWE-532

**Vulnerable Code:**
```python
print(f"User {username} registered with password hash: {hashed}")
```

**Description:**  
Password hashes are written to logs/stdout. While not plaintext passwords, hashes can still be used in offline cracking attacks. Log files may be accessible to multiple staff members or logged to external systems.

**Remediation:**
```python
import logging
logger = logging.getLogger(__name__)

# Only log non-sensitive confirmation
logger.info(f"New user registered: {username} ({email})")
```

---

### VUL-09 — Missing Input Validation
**Severity:** MEDIUM  
**Location:** `register_user()` function  
**CWE:** CWE-20

**Vulnerable Code:**
```python
def register_user(username, password, email, role="user"):
    # No validation whatsoever
    conn.execute("INSERT INTO users ...", (username, hashed, email, role))
```

**Description:**  
No validation is performed on any input. This allows empty fields, invalid email formats, extremely short passwords, and — critically — a caller assigning any `role` value (including `"admin"`) to themselves.

**Remediation:**
```python
def validate_username(username: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_]{3,30}$', username))

def validate_password(password: str) -> bool:
    return len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password)

def validate_email(email: str) -> bool:
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,}$', email))

# In register_user — validate and restrict role assignment
if role not in ("user", "moderator"):
    raise ValueError("Invalid role.")
```

---

### VUL-10 — Verbose Error Messages
**Severity:** MEDIUM  
**Location:** `get_user()` function  
**CWE:** CWE-209

**Vulnerable Code:**
```python
except Exception as e:
    return f"Database error: {str(e)}"
```

**Description:**  
Raw exception messages are returned to the caller and potentially displayed to end users. These messages can reveal database schema, table names, column names, or server paths — information that assists attackers in crafting further attacks.

**Remediation:**
```python
except Exception:
    logger.error("Database error in get_user", exc_info=True)  # Full detail goes to logs only
    return None  # Return neutral value to caller — never raw exception
```

---

## Summary Table

| ID | Vulnerability | Severity | CWE | Status |
|----|--------------|----------|-----|--------|
| VUL-01 | SQL Injection | CRITICAL | CWE-89 | Fixed in secure_app.IPYNB |
| VUL-02 | Hardcoded Credentials | CRITICAL | CWE-798 | Fixed in secure_app.IPYNB |
| VUL-03 | Command Injection | CRITICAL | CWE-78 | Fixed in secure_app.IPYNB |
| VUL-04 | Insecure Deserialization | CRITICAL | CWE-502 | Fixed in secure_app.IPYNB |
| VUL-05 | Weak Hashing (MD5) | HIGH | CWE-916 | Fixed in secure_app.IPYNB |
| VUL-06 | Path Traversal | HIGH | CWE-22 | Fixed in secure_app.IPYNB |
| VUL-07 | Insecure Randomness | HIGH | CWE-338 | Fixed in secure_app.IPYNB |
| VUL-08 | Sensitive Data in Logs | HIGH | CWE-532 | Fixed in secure_app.IPYNB |
| VUL-09 | Missing Input Validation | MEDIUM | CWE-20 | Fixed in secure_app.IPYNB |
| VUL-10 | Verbose Error Messages | MEDIUM | CWE-209 | Fixed in secure_app.IPYNB |

---

## Recommendations

1. **Adopt a Secure SDLC** — Integrate security reviews at every stage of development, not just at the end.
2. **Use a Static Analyzer** — Tools like `bandit` (Python) can automatically detect many of these issues: `pip install bandit && bandit vulnerable_app.py`
3. **Never trust user input** — Validate, sanitize, and escape all data that enters your application from any external source.
4. **Use proven libraries** — Don't implement your own cryptography. Use `bcrypt`, `argon2`, or `secrets` from the standard library.
5. **Secrets management** — Use environment variables or a dedicated secrets manager. Never commit credentials to version control.
6. **Principle of least privilege** — Database users, file access, and OS permissions should be restricted to only what is necessary.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Manual Code Review | Primary audit method |
| Python `bandit` | Static analysis for common security issues |
| OWASP Top 10 | Reference for vulnerability classification |
| CWE Database | Standardized vulnerability taxonomy |

---

