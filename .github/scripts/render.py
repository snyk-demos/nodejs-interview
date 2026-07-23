#!/usr/bin/env python3
"""Render a Snyk result file (SARIF or Snyk Open Source JSON) as Markdown.

One renderer for all four scan types. Format is auto-detected from the
payload, so SAST / IaC / Container (SARIF) and SCA (Snyk JSON) share a
single implementation instead of four copies embedded in YAML heredocs.

Environment:
  RENDER_FILE   path to the results file                 (required)
  RENDER_TITLE  optional H2 heading for the section
  RENDER_EXIT   Snyk CLI exit code; 3 means nothing to scan
  RENDER_OUT    markdown file to append to               (default report.md)
"""
import json
import os

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_ICON = {"critical": "\U0001F6A8", "high": "\U0001F534",
            "medium": "\U0001F7E0", "low": "\U0001F7E1"}
SEV_LABEL = {"critical": "Critical", "high": "High",
             "medium": "Medium", "low": "Low"}
LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "low"}
# Every section collapsed. The severity table is the only thing visible until
# someone chooses to expand a section.
OPEN_BY_DEFAULT = set()
LIMIT = 25


def load(path):
    try:
        with open(path) as f:
            d = json.load(f)
        # snyk test on a multi-manifest repo emits a JSON array
        return d[0] if isinstance(d, list) and d else d
    except Exception:
        return None


def details_block(sev, count, rows):
    o = " open" if sev in OPEN_BY_DEFAULT else ""
    return ([f"<details{o}>",
             f"<summary>{SEV_ICON[sev]} <b>{SEV_LABEL[sev]}</b>: {count} issue(s)</summary>",
             ""] + rows + ["", "</details>", ""])


def bucket(items, key):
    out = {}
    for i in items:
        out.setdefault(key(i), []).append(i)
    return out


def counts_table(prefix, by_sev):
    """Headline plus a severity table. This is the only thing visible by
    default; every findings section below it renders collapsed."""
    rows = [prefix, "", "| Severity | Count |", "|---|---|"]
    for s in SEV_ORDER:
        if s in by_sev:
            rows.append(f"| {SEV_ICON[s]} {SEV_LABEL[s]} | {len(by_sev[s])} |")
    return rows + [""]


def sarif_severity(result, rules):
    """Prefer Snyk's own severity property; fall back to the SARIF level.

    Container and IaC SARIF carry a real critical/high/medium/low; Snyk Code
    only carries error/warning/note, which maps onto high/medium/low.
    """
    for src in (result.get("properties") or {}, rules.get(result.get("ruleId"), {}).get("properties") or {}):
        sev = str(src.get("severity", "")).lower()
        if sev in SEV_LABEL:
            return sev
    return LEVEL_TO_SEV.get(result.get("level"), "low")


def render_sarif(doc):
    run = (doc.get("runs") or [{}])[0]
    raw = ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []
    rules = {r.get("id"): r for r in raw}
    names = {rid: (r.get("shortDescription") or {}).get("text") or rid
             for rid, r in rules.items()}
    results = run.get("results") or []
    if not results:
        return ["\u2705 No findings."]

    by_sev = bucket(results, lambda r: sarif_severity(r, rules))
    out = counts_table(f"**{len(results)} findings**", by_sev)
    for sev in SEV_ORDER:
        if sev not in by_sev:
            continue
        rows = ["| Issue | Location |", "|---|---|"]
        for r in by_sev[sev][:LIMIT]:
            loc = (r.get("locations") or [{}])[0].get("physicalLocation") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri", "?")
            line = (loc.get("region") or {}).get("startLine", "?")
            rid = r.get("ruleId")
            rows.append(f"| {names.get(rid, rid)} | `{uri}:{line}` |")
        if len(by_sev[sev]) > LIMIT:
            rows += ["", f"...plus {len(by_sev[sev]) - LIMIT} more, see the run log."]
        out += details_block(sev, len(by_sev[sev]), rows)
    return out


def render_sca(doc):
    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        return ["\u2705 No high/critical dependency issues."]

    uniq = {}
    for v in vulns:
        uniq.setdefault(v.get("id"), v)
    by_sev = bucket(uniq.values(), lambda v: v.get("severity", "low"))
    out = counts_table(
        f"**{len(uniq)} unique issues across {len(vulns)} vulnerable paths**", by_sev)

    for sev in SEV_ORDER:
        if sev not in by_sev:
            continue
        rows = ["| Issue | Package | Fixed in |", "|---|---|---|"]
        for v in sorted(by_sev[sev], key=lambda x: x.get("packageName", "")):
            fixed = ", ".join((v.get("fixedIn") or [])[:3]) or "-"
            rows.append(f"| {v.get('title', '?')} | "
                        f"`{v.get('packageName', '?')}@{v.get('version', '?')}` | `{fixed}` |")
        out += details_block(sev, len(by_sev[sev]), rows)

    remediation = doc.get("remediation") or {}
    upgrades = remediation.get("upgrade") or {}
    if upgrades:
        rows = ["| Upgrade | To | Fixes |", "|---|---|---|"]
        ranked = sorted(upgrades.items(), key=lambda kv: -len(kv[1].get("vulns", [])))
        for pkg, info in ranked[:10]:
            rows.append(f"| `{pkg}` | `{info.get('upgradeTo', '?')}` | "
                        f"{len(info.get('vulns', []))} issues |")
        out += (["<details>",
                 "<summary>\U0001F527 <b>Top fixes by impact</b> (bump these first)</summary>",
                 ""] + rows + ["", "</details>", ""])

    unresolved = remediation.get("unresolved") or []
    if unresolved:
        out += [f"\u26A0\uFE0F {len(unresolved)} issues have **no direct upgrade** "
                "(transitive pins), see run log.", ""]
    return out


def render(path):
    doc = load(path)
    if not doc:
        return ["\u26A0\uFE0F Scan produced no output. Check the step log."]
    if doc.get("runs"):
        return render_sarif(doc)
    if "vulnerabilities" in doc:
        return render_sca(doc)
    return ["\u26A0\uFE0F Unrecognised result format. Check the step log."]


def main():
    title = os.environ.get("RENDER_TITLE", "")
    lines = [f"## {title}", ""] if title else []
    if os.environ.get("RENDER_EXIT") == "3":
        lines += ["\u2139\uFE0F No supported files for this scan type in the repo, "
                  "nothing to scan."]
    else:
        lines += render(os.environ["RENDER_FILE"])
    lines.append("")
    with open(os.environ.get("RENDER_OUT", "report.md"), "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
