# Blind SQLi (Conditional Responses) — PortSwigger Lab Writeup

So this one looks easy on paper but took me way longer than I expected, mostly because of Burp Community's Intruder being slow and my lab instance resetting on me a couple of times mid-extraction (lesson learned: don't close your laptop mid-lab, the session dies and you get a fresh randomized password 💀).

**Lab:** [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
**Difficulty:** Practitioner
**Status:** Solved ✅

---

## The setup

App sets a `TrackingId` cookie for analytics. No errors, no data reflected anywhere — but if you send a cookie value the backend recognizes, you get a `Welcome back!` message somewhere in the page. That's it. That's the only signal you get.

Reconstructed query looks something like:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '<cookie value>'
```

No output, no errors — classic blind SQLi setup.

## Step 1 — confirm it's actually injectable

Threw a basic boolean test at it:

```
TrackingId=abc' AND '1'='1
```
→ Welcome back shows up.

```
TrackingId=abc' AND '1'='2
```
→ Disappears.

Good, that's a working true/false oracle. Now I can ask the database yes/no questions and read the answer purely from whether that message shows up.

## Step 2 — pull the password out one character at a time

Used `SUBSTRING()` to ask about individual characters of the admin's password:

```sql
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) = 'a
```

Did a manual binary search on the first character just to make sure I actually understood what was happening instead of just letting a tool do it blindly (highly recommend doing this at least once — way easier to explain in an interview than "I ran a tool").

Manually narrowed it down: `> 'm` → true, `> 't'` → true, `> 'w'` → true, `> 'y'` → true, `= 'z'` → confirmed. First char is `z`.

## Step 3 — automate the rest with Intruder

Doing this by hand for a 20-character password would've taken forever (and the 2nd character wasn't even a letter — it was `9`, so lowercase-only wouldn't have caught it anyway). Set up Burp Intruder:

- Sent the request with a placeholder at the position I was testing: `...),N,1) = '§X§`
- Payload list: a-z, A-Z, 0-9 (Community Edition doesn't have the "numbers" payload generator Pro has, so had to paste this in manually — annoying but whatever, free tool)
- Sorted results by response **Length** — the row with a different length than everyone else is your answer (longer response = "Welcome back!" is present)

Repeated this per character position, confirming each one manually in Repeater before moving to the next (burned once by trusting the sorted table without double-checking — got a wrong letter on one position when I didn't re-verify, so now I always confirm with `=` directly before locking it in).

Kept going until I had the full password.

## Final password

```
rf5a7rtpxzfoxpw9s55z
```

20 characters — no dictionary pattern, fully random, which tracks for a lab environment.

Logged in as `administrator`, lab marked solved.

## What actually slowed me down (being honest)

- Burp Community's Intruder threw random "Communication error" timeouts a few times during longer attack runs — had to restart Burp clean more than once
- Lab instances reset after inactivity (closed laptop, took a break) — each reset = brand new random password, so any progress from before is void. Found this out the hard way after getting to character 14 twice.
- The response search box in Burp doesn't auto-search — easy to think a true result is false just because you forgot to type "Welcome" into the search field again after sending a new request

## Why this matters

No error messages, no reflected data — this is the kind of SQLi that a lot of basic scanners miss entirely because it doesn't trip typical SQLi detection patterns (no SQL syntax errors returned). You genuinely have to notice a subtle behavioral difference in the response and manually (or semi-automatically) extract data bit by bit. Good reminder that automated scanners aren't a substitute for actually understanding how the injection works.

## Fix

Parameterized queries. Don't build SQL by string-concatenating anything user-controlled into a query — including cookies and headers, not just form inputs. Least-privilege DB accounts help limit blast radius too.

---

*Part of my ongoing PortSwigger Web Security Academy run-through — see [repo root](../../) for other writeups.*
