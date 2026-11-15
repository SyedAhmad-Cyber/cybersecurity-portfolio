# Lab: SQL Injection UNION Attack: Querying Database Type and Version (MySQL & Microsoft)

## Objective
Extract the exact database software and operating system version string by injecting a UNION query into the vulnerable product category filter.

## Vulnerability Summary
The `category` parameter in the `/filter` endpoint takes user input directly from the URL and passes it into a backend SQL query without proper sanitization. Breaking out of the string literal with a single quote allows an attacker to append custom SQL commands and read internal database variables.

## Exploitation Steps

1. First, I tested the column count using `ORDER BY` clauses and confirmed the original query returns 2 columns when the application loaded normally.
2. Next, I checked which column could safely render text back to the user by injecting `' UNION SELECT 'a', NULL#` into the parameter, which verified that column 1 accepts string data.
3. Finally, I replaced the test string with `@@version` to extract the live database environment details.

### Extracted Artifact / Output
* **Database Version String:** `8.0.42-0ubuntu0.20.04.1`

### Final Payload (Browser URL)

    .../filter?category=Gifts'+UNION+SELECT+@@version,+NULL%23

### Raw SQL Payload

    ' UNION SELECT @@version, NULL#

## Payload Breakdown
* The single quote `'` closes out the original text parameter in the backend query.
* `UNION SELECT` appends our custom query results to the application's original output.
* `@@version` is a built-in system variable in MySQL and Microsoft SQL Server that pulls the exact release and OS build.
* `NULL` acts as a placeholder for the second column so both queries have matching column counts.
* `%23` (`#`) is the URL-encoded comment character that tells the database to ignore the rest of the original developer query.

## Business Impact
Knowing the exact database version and OS build allows an attacker to research specific unpatched CVEs for that exact software release, potentially leading to remote code execution or total server compromise.

## How to Fix (Remediation)
* Implement parameterized queries (prepared statements) so user input is handled strictly as data rather than executable code.
* Apply strict allowlist validation on the `category` parameter to ensure only expected input values are processed.
