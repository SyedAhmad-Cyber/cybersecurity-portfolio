# SQL Injection: Enumerating Database Contents on Non-Oracle Databases

* **Platform:** PortSwigger Web Security Academy
* **Category:** SQL Injection (UNION-Based Schema Enumeration)
* **Difficulty:** Practitioner
* **Status:** Solved

---

## Executive Summary

A UNION-based SQL injection vulnerability was identified in the `category` parameter of the product filtering endpoint (`/filter?category=`). Because the application concatenates unsanitized user input directly into backend SQL queries, an attacker can append arbitrary `UNION SELECT` statements to query system metadata views. By enumerating `information_schema.tables` and `information_schema.columns`, the database layout was mapped, exposing a custom user table (`users_ioumxv`). Extracting the cleartext records from this table yielded the `administrator` credentials, resulting in full administrative account takeover.

---

## Technical Walkthrough & Lab Artifacts

### 1. Recon & Column Enumeration
The product category filter reflects query results directly within the HTML response. Probing the endpoint confirmed that the original query returns **2 columns**, both capable of rendering text strings on the page.

### 2. Table Discovery via `information_schema.tables`
Non-Oracle relational databases (such as PostgreSQL, MySQL, and Microsoft SQL Server) maintain a built-in metadata directory called `information_schema`. Querying `table_name` from `information_schema.tables` listed all tables present in the database, revealing a randomized table used for authentication:

* **Discovered Table:** `users_ioumxv`

### 3. Column Discovery via `information_schema.columns`
Filtering `information_schema.columns` for records matching `table_name = 'users_ioumxv'` exposed the exact field names storing user credentials:

* **Username Column:** `username_vaztjd`
* **Password Column:** `password_vlgvwb`

### 4. Credential Exfiltration & Account Takeover
Querying `username_vaztjd` and `password_vlgvwb` directly from `users_ioumxv` returned the stored user records in the application response:

* **Target Account:** `administrator`
* **Extracted Password:** `lc401q13vm8cgzhday83`

Submitting these credentials at the `/login` endpoint granted full administrative access to the application.

---

## Business Impact

* **Complete Authentication Bypass & Privilege Escalation:** Compromising the `administrator` account grants an attacker unrestricted access to administrative panels, user management controls, and sensitive business operations.
* **Failure of Security Through Obscurity:** Randomizing table and column names (`users_ioumxv`, `username_vaztjd`, `password_vlgvwb`) does not protect sensitive data when `information_schema` is accessible. An attacker can systematically map and exfiltrate the entire database, including Personally Identifiable Information (PII), financial records, and proprietary business data.
* **Regulatory & Reputational Risk:** Bulk exposure of user credentials constitutes a severe data breach, exposing the organization to compliance penalties (such as GDPR) and long-term loss of customer trust.

---

## Remediation

### 1. Parameterized Queries (Prepared Statements)
Eliminate dynamic string concatenation when constructing SQL queries. Use parameterized queries across all database access layers so the database engine compiles the SQL structure first and treats user input strictly as inert data.

**Vulnerable Pattern:**
```python
query = "SELECT * FROM products WHERE category = '" + category + "'"
