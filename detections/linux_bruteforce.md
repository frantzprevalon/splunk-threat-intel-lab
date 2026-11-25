# Linux - Brute Force Detection

**MITRE ATT&CK:** T1110 - Brute Force
**Data source:** `index=linux sourcetype=linux_secure` (/var/log/auth.log)
**Schedule:** Hourly alert, throttled 60 minutes

## What it detects
3 or more failed sudo/authentication attempts by the same user on the same host.

## SPL
```
index=linux sourcetype=linux_secure ("authentication failure" OR "incorrect password")
| rex "logname=(?<logname>\S+)"
| rex "sudo:\s+(?<sudo_user>\S+)\s+:"
| eval user=coalesce(user, logname, sudo_user)
| stats count by user, host
| where count >= 3
```

## How to test
1. `sudo -k`
2. `sudo ls` and enter a wrong password 3 times (repeat twice)
3. Run the search over the last 15 minutes

## Tuning notes
The first version returned no results: `stats by user` dropped events with no `user` field,
and sudo logs one summary line per 3 failed tries. Fixed by pulling the username from
`logname=` and the sudo summary line with `rex`, then merging them with `coalesce`.

## False positives
- A user mistyping their password several times
- Automation with expired credentials
