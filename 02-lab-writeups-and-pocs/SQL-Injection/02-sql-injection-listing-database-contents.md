# SQL Injection: Enumerating Database Contents on Non-Oracle Databases

* **Platform:** PortSwigger Web Security Academy
* **Category:** SQL Injection (UNION-Based / Schema Enumeration)
* **Difficulty:** Practitioner
* **Status:** Solved

---

## Executive Summary

I found a UNION-based SQL injection vulnerability in the `category` parameter of the product filtering endpoint. Because the application concatenates user input directly into the backend SQL query, I was able to append custom `UNION SELECT` statements. By querying system metadata views (`information_schema`), I mapped out the database layout, tracked down a randomized user table (`users_ioumxv`), extracted the administrator credentials, and took over the account.

---

## Technical Walkthrough & Lab Artifacts

### 1. Recon & Column Enumeration
The product category filter reflects query results right back into the HTML page. Before pulling database structure, I tested the endpoint to figure out how many columns the query handles and which ones accept strings:
* Used `ORDER BY` to find that the query returns **2 columns**.
* Tested with `UNION SELECT 'a', 'b'` to confirm both columns can render text.

### 2. Table Discovery via `information_schema.tables`
Since this lab runs on a non-Oracle database (PostgreSQL), it maintains a built-in metadata directory called `information_schema`. I queried `table_name` from `information_schema.tables` to list everything in the database:

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

Scanning through the rendered list of tables, I spotted the custom authentication table:
* **Discovered Table:** `users_ioumxv`

### 3. Column Discovery via `information_schema.columns`
With the target table isolated, I queried `information_schema.columns` where the table name matched `users_ioumxv` to find the exact column headers holding the credentials:

```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_ioumxv'--
```

The output exposed the randomized column names:
* **Username Column:** `username_vaztjd`
* **Password Column:** `password_vlgvwb`

### 4. Credential Exfiltration & Account Takeover
Using the exact table and column names I just mapped, I ran the final query to pull the user records:

```sql
' UNION SELECT username_vaztjd, password_vlgvwb FROM users_ioumxv--
```

The page dumped the database rows directly into the product slots, revealing the credentials:
* **Target Account:** `administrator`
* **Extracted Password:** `lc401q13vm8cgzhday83`

I plugged those credentials into the `/login` panel and successfully logged in as the administrator.

---

## Business Impact

* **Complete Authentication Bypass & Privilege Escalation:** Taking over the `administrator` account gives an attacker total control over the application backend, user management, and sensitive operations.
* **Security Through Obscurity Fails:** Randomizing table and column names (`users_ioumxv`, `username_vaztjd`, `password_vlgvwb`) doesn't actually stop anyone when `information_schema` is exposed. An attacker can easily map out the entire schema in minutes.
* **Compliance & Data Breaches:** Leaking cleartext credentials in bulk violates data protection regulations and destroys user trust.

---

## Remediation

### 1. Parameterized Queries (Prepared Statements)
Stop concatenating strings directly into SQL queries. Use parameterized queries across the application so the database treats user input strictly as inert data rather than executable code.

**Vulnerable Pattern:**
```python
query = "SELECT * FROM products WHERE category = '" + category + "'"
```

**Secure Pattern:**
```python
cursor.execute("SELECT * FROM products WHERE category = %s", (category,))
```

### 2. Allowlist Input Validation
Apply strict server-side validation on the `category` parameter. Compare incoming requests against an explicit allowlist of valid category names (`Gifts`, `Lifestyle`, `Tech gifts`) and drop anything that doesn't match an exact expected value.

### 3. Principle of Least Privilege & Hashing
* **Database Roles:** Restrict the web application's database user so it only has permissions on the specific tables it needs, removing access to system metadata views if they aren't required.
* **Credential Storage:** Store all passwords using strong, salted cryptographic hashing algorithms (like Argon2id or bcrypt) instead of cleartext.
