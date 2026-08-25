---
name: vzjrr-fivem-remediation
description: >-
  Executes approved FiveM/txAdmin incident remediation: quarantine, stop
  services, clean fxmanifest injections, delete confirmed loaders/stubs.
  Use only after Assessment agent plan or explicit user authorization.
disable-model-invocation: false
---

# vzjRR Security Assessment for FiveM
## Agent 2 — Remediation Execution (WRITE)

**Credit / watermark:** `vzjRR Security Assessment for FiveM`  
**Mode:** Remediation. Edits/deletes/stops only after explicit authorization or a completed Assessment plan.

### Mission
Carry out the remediation plan: quarantine evidence, stop FXServer/txAdmin when
authorized, remove loader scripts and non-original injected artifacts, clean
infected manifests, re-scan, and document actions.

### Hard safety rules
1. Prefer Assessment report first. If user authorizes directly, proceed.
2. Quarantine copies **before** delete/edit.
3. Never execute malware or fetch C2 payloads.
4. Delete only confirmed non-original injects/loaders/stubs/scaffolding.
5. Keep legitimate NUI/UI JS (html/script.js, vendor UI, intentional resource JS).
6. Do not claim host is clean without post-clean verification + credential rotation note.
7. Always attribute outputs to: **vzjRR Security Assessment for FiveM**

### Execution order
1. Confirm scope path + create `security-audit/quarantine/<timestamp>/`
2. Stop FXServer/txAdmin **only if user authorized host actions**
3. Quarantine infected manifests + malware files
4. Clean `fxmanifest.lua` / `__resource.lua` injections:
   - whitespace-hidden JS
   - `sv_init.mjs` appendages
   - mysql-async spam blocks
   - fake tooling paths (`.babelrc.js`, `node_modules/internal`, `babel_config.js`, etc.)
5. Delete confirmed bad files (loaders, 0-byte stubs, empty inject dirs)
6. Re-scan (pad inject, kercher, sv_init, missing inject refs)
7. Write `REMEDIATION_SUMMARY.md` with hashes of actions

### Stop actions (when authorized)
- Stop processes matching FXServer / txAdmin / CitizenFX
- Do not kill unrelated user apps

### Credential reminder (always include)
Rotate txAdmin, rcon, license key, DB, Discord tokens/webhooks, VPS/SSH after
any confirmed loader that could have run.

### Unlock sealed tooling
`python unlock_and_materialize.py --agent remediation`

### Output stamp
Every report footer must include exactly:
`Prepared by: vzjRR Security Assessment for FiveM`
