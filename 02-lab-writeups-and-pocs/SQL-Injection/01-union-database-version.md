# Lab: SQL Injection UNION Attack — Querying Database Type and Version (MySQL & Microsoft)

## Objective
Extract the exact database software and operating system version string by injecting a `UNION` query into a vulnerable product category filter.

## Vulnerability Summary
The `category` parameter in the `/filter` endpoint takes user input directly from the URL and places it into a backend SQL query without sanitization. By breaking out of the string with a single quote (`'`), an attacker can append custom SQL commands to read database system variables.

## Exploitation Steps

1. **Find Column Count:** Used `ORDER BY` to confirm the original query returns **2 columns**.
2. **Find Text Column:** Injected `' UNION SELECT 'a', NULL#` and confirmed **Column 1** displays text on the page.
3. **Extract Database Version:** Replaced `'a'` with the built-in system variable `@@version` to pull the database version and OS details.

### Final Payload (Browser URL)

    .../filter?category=Gifts'+UNION+SELECT+@@version,+NULL%23

### Raw SQL Payload

    ' UNION SELECT @@version, NULL#

## Payload Breakdown
* **`'`**: Closes out the original text parameter in the SQL query.
* **`UNION SELECT`**: Merges our custom query results with the original page output.
* **`@@version`**: Built-in system variable in MySQL and Microsoft SQL Server that returns the exact version string.
* **`NULL`**: Placeholder for the second column so both queries match in column count.
* **`%23` (`#`)**: URL-encoded comment character that tells the database to ignore the rest of the original query.

## How to Fix (Remediation)
* **Use Parameterized Queries (Prepared Statements):** Ensure user input is treated strictly as plain data, never as executable SQL code.
* **Allowlist Input Validation:** Restrict the `category` parameter so it only accepts known, valid category names.
