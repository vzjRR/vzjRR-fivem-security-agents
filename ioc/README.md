# IOC set

`iocs.json` is the machine-readable detection set used by everything in `tools/`. It is
plain text on purpose: you can read every rule before you run it, and change any of them.

## Structure

| Section | What it drives |
|---|---|
| `families` | Background on each malware family, including the extortion lock message fragments |
| `network_indicators` | Panel C2 domains, the `*-panel.*` naming pattern, Discord webhook exfil, payload-hosting endpoints, IP-literal endpoints |
| `code_signatures` | 33 regexes over Lua and JS: RCE loaders, shell execution, credential theft, console backdoors, obfuscation |
| `manifest_indicators` | Whitespace padding, JS-in-Lua resources, fake tooling paths, orphan references |
| `suspicious_filenames` | Known loader drop points |
| `txadmin_indicators` | Admin store, master account, bundle integrity, panel exposure |
| `servercfg_indicators` | ACE grants, chained `exec`, weak RCON, plaintext secrets |
| `host_persistence_indicators` | Windows and Linux persistence checks |
| `database_indicators` | Unknown accounts, wildcard grants, in-DB code staging |
| `reinfection_vectors` | The twelve re-entry paths, each with its closure action |
| `false_positive_guidance` | Noise reduction — it never clears a critical finding on its own |

## Safety

Every value here exists **only to be matched as text**. Never resolve, fetch, ping, or
connect to any domain, URL, webhook or IP in this file — including "just to check if it
is still up." Contacting attacker infrastructure confirms you are live and can trigger a
second stage.

## Extending it during an engagement

When you find a new indicator, add it before you finish, so the re-scan and the
verification pass both catch it:

```json
{ "id": "SIG-CUSTOM-001", "severity": "critical",
  "pattern": "your_regex_here",
  "why": "One sentence on what this means when it matches." }
```

Rules:

- **Regex must compile in both Python `re` and .NET** — the two scanners share this file.
  Stick to the common subset; avoid named groups and lookbehind.
- **Escape backslashes for JSON** (`\\.` for a literal dot).
- **Severity means something.** `critical` = a confirmed indicator justifying a
  compromised verdict. `high` = strong, still needs manual confirmation. `medium` = worth
  a look. Inflating severity makes the whole set less useful.
- **`why` is not optional.** A finding a server owner cannot act on is noise.
- Add incident-specific IPs under `network_indicators.incident_context_ips.values` —
  only ones you observed in your own logs, never pre-loaded blocklists.

Validate before committing:

```bash
python3 -c "
import json,re
d=json.load(open('ioc/iocs.json'))
for s in d['code_signatures']: re.compile(s['pattern'])
print('OK -', len(d['code_signatures']), 'signatures compile')"
```

---
Prepared by: vzjRR Security Assessment for FiveM
