#!/usr/bin/env python3
"""
vzjRR Security Assessment for FiveM - cross-platform read-only resource scanner.

Detects the Blum / Kercher / generic "-panel" FiveM backdoor family:
whitespace-padded fxmanifest injections, hidden loader scripts, remote-code-execution
patterns, credential-theft code and extortion lock strings.

READ-ONLY GUARANTEE: this script opens files for reading only. It never writes,
moves, deletes or executes anything inside the target tree, and never contacts any
network endpoint - including indicators it finds.

Usage:
    python3 vzjrr_scan.py --path /path/to/server-root --out /path/outside/target
    python3 vzjrr_scan.py --path C:\\FXServer\\server-data --out C:\\vzjrr-audit --since-days 30

Exit codes: 0 = no findings, 1 = high findings, 2 = critical findings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

CREDIT = "vzjRR Security Assessment for FiveM"

TEXT_EXT = {
    ".lua", ".js", ".mjs", ".cjs", ".json", ".cfg", ".txt", ".md", ".yml", ".yaml",
    ".ts", ".html", ".css", ".sql", ".bat", ".ps1", ".sh", ".env", ".ini", ".conf",
}
SCRIPT_EXT = {".lua", ".js", ".mjs", ".cjs"}
MANIFEST_NAMES = {"fxmanifest.lua", "__resource.lua"}
TOOLKIT_MARKER = ".vzjrr-toolkit-root"

FAKE_TOOLING = [
    "sv_init.mjs", "sv_init.js", ".babelrc.js", "babel_config.js", "babel.config.js",
    "crypto.js", ".yarn.js", "node_modules/internal", "webpack.config.js", "sv_core.js",
]


class Finding(dict):
    pass


def load_iocs(explicit: str | None) -> dict:
    if explicit:
        p = Path(explicit)
    else:
        p = Path(__file__).resolve().parent.parent / "ioc" / "iocs.json"
    if not p.exists():
        raise SystemExit(f"IOC file not found: {p}\nPass --ioc /path/to/iocs.json")
    return json.loads(p.read_text(encoding="utf-8"))


def build_patterns(ioc: dict) -> list[tuple[str, str, re.Pattern, str]]:
    """Return (id, severity, compiled_regex, why)."""
    out: list[tuple[str, str, re.Pattern, str]] = []
    for s in ioc.get("code_signatures", []):
        try:
            rx = re.compile(s["pattern"], re.IGNORECASE)
        except re.error as e:
            print(f"  ! skipping bad pattern {s['id']}: {e}", file=sys.stderr)
            continue
        out.append((s["id"], s["severity"], rx, s["why"]))

    net = ioc.get("network_indicators", {})
    for d in net.get("domains_exact", []):
        out.append(("NET-DOMAIN", "critical", re.compile(re.escape(d), re.IGNORECASE),
                    f"Known malicious panel/C2 host: {d}"))
    for p in net.get("domain_patterns", []):
        out.append(("NET-PANEL", "critical", re.compile(p, re.IGNORECASE),
                    "Matches the *-panel C2 naming pattern used by this extortion family."))
    for p in net.get("exfil_patterns", []):
        out.append(("NET-EXFIL", "high", re.compile(p, re.IGNORECASE),
                    "Discord webhook - the usual exfiltration channel for stolen server credentials."))
    for p in net.get("payload_host_patterns", []):
        out.append(("NET-PAYLOAD", "high", re.compile(p, re.IGNORECASE),
                    "Known payload-hosting endpoint referenced in server code."))
    for ip in net.get("incident_context_ips", {}).get("values", []):
        out.append(("NET-INCIDENT-IP", "critical", re.compile(re.escape(ip)),
                    f"IP supplied as incident context: {ip}"))
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "unavailable"


def read_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def scan(root: Path, ioc: dict, since_days: int, max_mb: int) -> dict:
    patterns = build_patterns(ioc)
    crit_names = set(ioc["suspicious_filenames"]["critical"])
    high_names = set(ioc["suspicious_filenames"]["high"])
    max_bytes = max_mb * 1024 * 1024
    cutoff = time.time() - since_days * 86400

    findings: list[Finding] = []
    files: list[Path] = []
    manifests: list[Path] = []
    recent: list[dict] = []
    scanned = 0

    def add(fid, sev, rel, line, evidence, why):
        findings.append(Finding(id=fid, severity=sev, file=rel, line=line,
                                evidence=evidence, why=why))

    print(f"Enumerating {root} ...")
    pruned: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Never scan the toolkit's own tree: its IOC set and docs contain every pattern
        # by definition, and would otherwise produce a false COMPROMISED verdict when
        # the toolkit is cloned inside the server folder being scanned.
        if TOOLKIT_MARKER in filenames:
            dirnames[:] = []
            pruned.append(str(Path(dirpath)))
            continue
        dirnames[:] = [d for d in dirnames if d not in {".git", "cache", "logs"}]
        for name in filenames:
            fp = Path(dirpath) / name
            files.append(fp)
            if name in MANIFEST_NAMES:
                manifests.append(fp)
    print(f"{len(files)} files, {len(manifests)} manifests.")
    for d in pruned:
        print(f"  (excluded toolkit tree: {d})")

    print("Content signature scan ...")
    for fp in files:
        try:
            st = fp.stat()
        except OSError:
            continue
        rel = str(fp.relative_to(root))
        ext = fp.suffix.lower()

        if fp.name in crit_names:
            add("FILE-CRIT", "critical", rel, 0, fp.name,
                "Filename matches a known loader drop point for this malware family.")
        elif fp.name in high_names:
            add("FILE-HIGH", "high", rel, 0, fp.name,
                "Fake build-tooling filename used to disguise a loader inside a FiveM resource.")

        if st.st_size == 0 and ext in SCRIPT_EXT:
            add("FILE-STUB", "medium", rel, 0, "0 bytes",
                "Zero-byte script - typically a loader that wiped itself after execution, "
                "or a placeholder left behind by an incomplete cleanup.")

        if st.st_mtime > cutoff and ext in SCRIPT_EXT | {".cfg", ".json"}:
            recent.append({"file": rel,
                           "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})

        if ext not in TEXT_EXT or st.st_size > max_bytes:
            continue
        lines = read_lines(fp)
        if lines is None:
            continue
        scanned += 1

        # Match against the whole file body, not line by line: several loader
        # signatures deliberately span multiple lines (fetch on one line, eval on
        # the next). Line numbers are recovered from the match offset.
        body = "\n".join(lines)
        line_starts = [0]
        for ln in lines:
            line_starts.append(line_starts[-1] + len(ln) + 1)

        def line_of(offset: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= offset:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        seen: set[tuple[str, int]] = set()
        for fid, sev, rx, why in patterns:
            for m in rx.finditer(body):
                lineno = line_of(m.start())
                if (fid, lineno) in seen:
                    continue
                seen.add((fid, lineno))
                ev = lines[lineno - 1].strip() if lineno - 1 < len(lines) else m.group(0)
                if m.group(0).count("\n"):
                    ev = " ".join(m.group(0).split())
                if len(ev) > 240:
                    ev = ev[:240] + " ...[truncated]"
                add(fid, sev, rel, lineno, ev, why)

    print(f"{scanned} text files scanned.")

    print("Manifest injection audit ...")
    pad_rx = re.compile(r"[ \t]{60,}")
    ref_rx = re.compile(r"""['"]([A-Za-z0-9_\-./\\@\[\]]+\.(?:lua|js|mjs))['"]""")
    for mf in manifests:
        rel = str(mf.relative_to(root))
        res_dir = mf.parent
        lines = read_lines(mf)
        if lines is None:
            continue
        blank_run = 0
        for i, ln in enumerate(lines, start=1):
            if not ln.strip():
                blank_run += 1
                continue
            if blank_run >= 20:
                add("MAN-005", "high", rel, i, f"{blank_run} blank lines then: {ln.strip()[:160]}",
                    "Content hidden behind a large blank gap so it scrolls out of the editor view.")
            blank_run = 0

            if pad_rx.search(ln) and ln.strip():
                add("MAN-001", "critical", rel, i, "PADDED: " + ln.strip()[:200],
                    "Whitespace-padded manifest line - the signature Blum/Kercher injection. "
                    "The padding pushes the malicious directive beyond the editor viewport so it is "
                    "invisible unless you scroll right or grep for it.")

            low = ln.lower()
            for fake in FAKE_TOOLING:
                if fake in low:
                    add("MAN-003", "critical", rel, i, ln.strip()[:200],
                        f"Manifest references '{fake}' - a fake build-tooling path used as a loader entry point.")

            for m in ref_rx.finditer(ln):
                ref = m.group(1)
                if "*" in ref or "?" in ref or ref.startswith("http"):
                    continue
                target = res_dir / ref.replace("\\", "/")
                if not target.exists():
                    add("MAN-006", "high", rel, i, ref,
                        f"Manifest loads '{ref}' but that file is not on disk. Either a loader deleted "
                        "itself after running, or a previous cleanup removed the file and left the "
                        "reference behind - both mean this resource needs a history review.")

        body = "\n".join(lines)
        if re.search(r"server_scripts?\s*[\{\(']?[^\n]*\.(js|mjs)", body, re.IGNORECASE):
            lua_files = list(res_dir.rglob("*.lua"))
            js_top = list(res_dir.glob("*.js")) + list(res_dir.glob("*.mjs"))
            if lua_files and js_top:
                add("MAN-002", "high", rel, 0, "server_script -> .js/.mjs in a Lua resource",
                    "A Lua resource that also loads a server-side JS file. Legitimate for a small set of "
                    "known resources (oxmysql, screenshot-basic); a strong injection signal otherwise.")

    print("Hashing flagged files ...")
    hashes = {}
    for rel in sorted({f["file"] for f in findings}):
        fp = root / rel
        if fp.is_file():
            hashes[rel] = sha256(fp)

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium")}
    if counts["critical"]:
        verdict = "COMPROMISED - critical indicators present"
    elif counts["high"]:
        verdict = "SUSPECTED COMPROMISE - high-severity indicators need manual confirmation"
    elif counts["medium"]:
        verdict = "INCONCLUSIVE - medium indicators only"
    else:
        verdict = ("NO RESOURCE-TREE INDICATORS FOUND (this does NOT mean the host is clean - "
                   "run the host audit and complete credential rotation)")

    recent.sort(key=lambda r: r["mtime"], reverse=True)
    return {
        "credit": CREDIT,
        "excluded_toolkit_trees": pruned,
        "scanned_utc": datetime.now(timezone.utc).isoformat(),
        "target": str(root),
        "ioc_version": ioc.get("version"),
        "files_total": len(files),
        "files_scanned": scanned,
        "manifests": len(manifests),
        "counts": counts,
        "verdict": verdict,
        "findings": findings,
        "hashes": hashes,
        "recent_changes": recent[:200],
    }


def md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def write_report(result: dict, outdir: Path) -> tuple[Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    jp = outdir / "resource-scan.json"
    jp.write_text(json.dumps(result, indent=2), encoding="utf-8")

    c = result["counts"]
    lines = [
        "# FiveM Resource Scan Report",
        "",
        f"- **Target:** `{result['target']}`",
        f"- **Scanned (UTC):** {result['scanned_utc']}",
        f"- **IOC set:** {result.get('ioc_version')}",
        f"- **Files:** {result['files_total']} total, {result['files_scanned']} text files scanned, "
        f"{result['manifests']} manifests",
        f"- **Findings:** {c['critical']} critical / {c['high']} high / {c['medium']} medium",
        f"- **Verdict:** {result['verdict']}",
        "",
        "> A clean resource scan does not mean a clean server. Host persistence, txAdmin admin "
        "accounts and stolen credentials all survive file cleanup. Complete the host audit and the "
        "credential rotation before declaring recovery.",
        "",
    ]
    for sev in ("critical", "high", "medium"):
        subset = [f for f in result["findings"] if f["severity"] == sev]
        if not subset:
            continue
        lines += [f"## {sev.upper()} ({len(subset)})", "",
                  "| ID | File | Line | Evidence | Why it matters |", "|---|---|---|---|---|"]
        for f in subset:
            lines.append(f"| {f['id']} | `{md_escape(f['file'])}` | {f['line']} | "
                         f"`{md_escape(f['evidence'])}` | {md_escape(f['why'])} |")
        lines.append("")
    if result["hashes"]:
        lines += ["## SHA-256 of flagged files", "", "| File | SHA-256 |", "|---|---|"]
        for k, v in sorted(result["hashes"].items()):
            lines.append(f"| `{md_escape(k)}` | `{v}` |")
        lines.append("")
    lines += ["---", f"Prepared by: {CREDIT}"]
    mp = outdir / "resource-scan.md"
    mp.write_text("\n".join(lines), encoding="utf-8")
    return mp, jp


def main() -> int:
    ap = argparse.ArgumentParser(description=f"FiveM read-only backdoor scanner - {CREDIT}")
    ap.add_argument("--path", required=True,
                    help="Server ROOT (the folder containing resources/, server.cfg, txData/). "
                         "Scoping this to resources/ alone is how re-entry paths get missed.")
    ap.add_argument("--out", default="", help="Report output directory - must be OUTSIDE the target tree.")
    ap.add_argument("--ioc", default="", help="Path to iocs.json (default: ../ioc/iocs.json).")
    ap.add_argument("--since-days", type=int, default=30)
    ap.add_argument("--max-mb", type=int, default=12)
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a directory: {root}")
    out = Path(args.out).resolve() if args.out else \
        Path.cwd() / "vzjrr-audit" / datetime.now().strftime("%Y%m%d-%H%M%S")
    if str(out).startswith(str(root)):
        raise SystemExit("--out must be OUTSIDE the target tree. "
                         "Evidence written inside a compromised tree is not evidence.")

    print(f"{CREDIT}\nTarget: {root}\nOutput: {out}\n")
    ioc = load_iocs(args.ioc or None)
    result = scan(root, ioc, args.since_days, args.max_mb)
    mp, jp = write_report(result, out)

    print()
    for f in result["findings"]:
        if f["severity"] in ("critical", "high"):
            print(f"[{f['severity'].upper():8}] {f['file']}:{f['line']}  {f['id']}")
    print(f"\nVERDICT: {result['verdict']}")
    print(f"Report : {mp}\nJSON   : {jp}\nPrepared by: {CREDIT}")

    if result["counts"]["critical"]:
        return 2
    if result["counts"]["high"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
