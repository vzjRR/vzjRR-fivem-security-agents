# vzjRR Security Assessment for FiveM

Defensive **FiveM / txAdmin** incident-response agents.

**Credit:** `vzjRR Security Assessment for FiveM`

---

## Use with any AI (no download required)

Paste **one** of these prompts into Cursor / ChatGPT / Claude / etc.

### 1) Assessment only (read-only scan + plan)

```text
Fetch and follow this agent exactly (read-only). Do not download zip files. Do not remediate yet.
https://raw.githubusercontent.com/vzjRR/vzjRR-fivem-security-agents/main/agents/assessment/AGENT.md

Target path: PASTE_YOUR_FIVEM_OR_RESOURCES_PATH_HERE
```

### 2) Remediation (edit / delete / stop) — only after assessment or your OK

```text
Fetch and follow this agent exactly. Do not download zip files.
https://raw.githubusercontent.com/vzjRR/vzjRR-fivem-security-agents/main/agents/remediation/AGENT.md

Target path: PASTE_YOUR_FIVEM_OR_RESOURCES_PATH_HERE
Authorized: yes — quarantine, clean manifests, delete confirmed loaders/stubs
```

### 3) Full workflow (assessment then remediation)

```text
1) Fetch and run this assessment agent (read-only):
https://raw.githubusercontent.com/vzjRR/vzjRR-fivem-security-agents/main/agents/assessment/AGENT.md
Target: PASTE_PATH_HERE

2) After the report, if compromised, fetch and run remediation:
https://raw.githubusercontent.com/vzjRR/vzjRR-fivem-security-agents/main/agents/remediation/AGENT.md
Same target. Quarantine before delete. Re-scan after cleanup.
Credit all output as: vzjRR Security Assessment for FiveM
```

---

## Agents

| Agent | Path | Mode |
|-------|------|------|
| Assessment & Planning | [`agents/assessment/AGENT.md`](agents/assessment/AGENT.md) | Read-only |
| Remediation Execution | [`agents/remediation/AGENT.md`](agents/remediation/AGENT.md) | Write / delete / stop |

## Optional sealed ZIP packages

Local encrypted toolkits (optional — **not required** for link-based AI use):

- [`dist/vzjRR_FiveM_Assessment_Agent.zip`](dist/vzjRR_FiveM_Assessment_Agent.zip)
- [`dist/vzjRR_FiveM_Remediation_Agent.zip`](dist/vzjRR_FiveM_Remediation_Agent.zip)

Unlock keys are **never** stored in this repository.

## Safety

- Defensive IR only. Do not detonate malware or fetch C2 payloads.
- Assessment never modifies the suspect tree.
- Remediation quarantines first, then cleans confirmed injections/loaders.

---

Prepared by: **vzjRR Security Assessment for FiveM**
