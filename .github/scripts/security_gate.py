#!/usr/bin/env python3
"""Poort van de pipeline: laat de run falen bij een NIEUWE kritieke bevinding.

Leest de resultaten van vijf controles:
  - SCA      : uitvoer van `dotnet list package --vulnerable --format json`
  - SAST     : SARIF-bestanden van CodeQL
  - Secrets  : JSON-rapport van gitleaks
  - Tests    : JSON van security_tests.py (gedrag van de draaiende app)
  - Container: SARIF van Trivy (image vulnerabilities + config issues)

Een bevinding is "aanvaard" als ze in .security/accepted-findings.json staat,
met een verdict en een reden. Een aanvaarding zonder reden laat de pipeline
ook falen. De poort faalt gesloten: ontbreekt een verwacht resultaatbestand,
dan is dat een fout en geen "geen bevindingen".

Wat is "kritiek"?
  - SCA     : severity High of Critical
  - SAST    : security-severity >= --min-sast-score (standaard 7.0),
              of level "error" als een regel geen score heeft
  - Secrets : elke gevonden geheim
  - Tests   : elke test die misbruik kan aantonen (elke test is een beveiligingseis)
  - Container: severity HIGH of CRITICAL (CVE's, misconfiguraties)

Enkel standaardbibliotheek, zodat er niets extra te installeren (en te vertrouwen) is.
"""
import argparse
import glob
import json
import os
import sys

TOOLS = ("sca", "sast", "secrets", "tests", "container")
VERDICTS = ("echt-probleem", "false-positive")
MIN_REASON_LEN = 15


class Finding:
    def __init__(self, tool, fid, severity, critical, text, alt_ids=(), **attrs):
        self.tool = tool
        self.id = fid
        self.severity = severity
        self.critical = critical
        self.text = text
        self.alt_ids = set(alt_ids)
        self.attrs = attrs  # file / package, gebruikt bij het matchen

    def where(self):
        if "package" in self.attrs:
            return self.attrs["package"]
        line = self.attrs.get("line")
        return f"{self.attrs.get('file', '?')}" + (f":{line}" if line else "")

    def key(self):
        return (self.tool, self.id, self.attrs.get("file"), self.attrs.get("package"))


def fail_closed(msg):
    print(f"::error::{msg}")
    sys.exit(2)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        fail_closed(f"Resultaatbestand ontbreekt of is onleesbaar: {path} ({exc})")
    start = min([i for i in (raw.find("{"), raw.find("[")) if i != -1], default=-1)
    if start == -1:
        fail_closed(f"Geen JSON gevonden in {path}")
    try:
        return json.loads(raw[start:])
    except json.JSONDecodeError as exc:
        fail_closed(f"Ongeldige JSON in {path}: {exc}")


# ----------------------------------------------------------------------------
# Parsers
# ----------------------------------------------------------------------------
def parse_sca(path):
    data = load_json(path)
    seen, out = set(), []
    for proj in data.get("projects", []):
        for fw in proj.get("frameworks", []):
            for kind in ("topLevelPackages", "transitivePackages"):
                for pkg in fw.get(kind, []):
                    name = f"{pkg.get('id')} {pkg.get('resolvedVersion', '?')}"
                    for vuln in pkg.get("vulnerabilities", []):
                        sev = vuln.get("severity", "Unknown")
                        url = vuln.get("advisoryurl", "")
                        vid = url.rstrip("/").split("/")[-1] or "onbekend"
                        if (vid, name) in seen:
                            continue
                        seen.add((vid, name))
                        out.append(Finding(
                            "sca", vid, sev, sev.lower() in ("high", "critical"),
                            f"{name} is kwetsbaar ({url})",
                            package=pkg.get("id"),
                        ))
    return out


def sarif_label(score, level):
    if score is None:
        return {"error": "high", "warning": "medium"}.get(level, "low")
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def parse_sarif(pattern, min_score):
    paths = sorted(glob.glob(pattern))
    if not paths:
        fail_closed(f"Geen SARIF-bestanden gevonden voor patroon {pattern}")
    out = []
    for path in paths:
        sarif = load_json(path)
        for run in sarif.get("runs", []):
            tool = run.get("tool", {})
            rules = {}
            for comp in [tool.get("driver", {})] + tool.get("extensions", []):
                for rule in comp.get("rules") or []:
                    rules[rule.get("id")] = rule
            for res in run.get("results", []):
                if res.get("suppressions"):
                    continue
                rid = res.get("ruleId") or res.get("rule", {}).get("id") or "onbekend"
                rule = rules.get(rid, {})
                score = (rule.get("properties") or {}).get("security-severity")
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    score = None
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level", "warning")
                critical = score >= min_score if score is not None else level == "error"
                loc = ((res.get("locations") or [{}])[0]).get("physicalLocation", {})
                out.append(Finding(
                    "sast", rid, sarif_label(score, level), critical,
                    " ".join(((res.get("message") or {}).get("text", "")).split()).replace("|", "/")[:160],
                    file=(loc.get("artifactLocation") or {}).get("uri", "?"),
                    line=(loc.get("region") or {}).get("startLine"),
                ))
    return out


def parse_secrets(path):
    data = load_json(path)
    if not isinstance(data, list):
        fail_closed(f"Verwacht een lijst in {path}")
    out = []
    for leak in data:
        out.append(Finding(
            "secrets", leak.get("Fingerprint") or leak.get("RuleID", "onbekend"),
            "critical", True,
            f"{leak.get('Description', 'geheim')} (regel {leak.get('RuleID')})",
            alt_ids=[leak.get("RuleID")],
            file=leak.get("File"), line=leak.get("StartLine"),
        ))
    return out


SKIPPED_TESTS = []


def parse_tests(path):
    data = load_json(path)
    if not isinstance(data, dict) or "findings" not in data:
        fail_closed(f"Verwacht een object met 'findings' in {path}")
    SKIPPED_TESTS.extend(data.get("skipped", []))
    out = []
    for t in data["findings"]:
        out.append(Finding(
            "tests", t.get("id", "onbekend"), t.get("severity", "high"), True,
            f"{t.get('title', '')} (verwacht {t.get('expected', '?')}, kreeg {t.get('actual', '?')})"[:200],
            file=t.get("endpoint"),
        ))
    return out


def parse_trivy(path):
    data = load_json(path)
    out = []
    for run in data.get("runs", []):
        tool = run.get("tool", {})
        rules = {}
        for comp in [tool.get("driver", {})] + tool.get("extensions", []):
            for rule in comp.get("rules") or []:
                rules[rule.get("id")] = rule
        for res in run.get("results", []):
            if res.get("suppressions"):
                continue
            rid = res.get("ruleId") or res.get("rule", {}).get("id") or "onbekend"
            rule = rules.get(rid, {})
            # Trivy SARIF: security-severity (CVSS score) of level
            score = (rule.get("properties") or {}).get("security-severity")
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = None
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level", "warning")
            critical = score >= 7.0 if score is not None else level == "error"
            sev = sarif_label(score, level)
            loc = ((res.get("locations") or [{}])[0]).get("physicalLocation", {})
            out.append(Finding(
                "container", rid, sev.upper(), critical,
                " ".join(((res.get("message") or {}).get("text", "")).split()).replace("|", "/")[:160],
                file=(loc.get("artifactLocation") or {}).get("uri", "?"),
            ))
    return out


# ----------------------------------------------------------------------------
# Aanvaarde bevindingen
# ----------------------------------------------------------------------------
def load_accepted(path):
    if not os.path.exists(path):
        return [], []
    entries = load_json(path)
    errors = []
    if not isinstance(entries, list):
        return [], ["accepted-findings.json moet een lijst zijn"]
    seen = set()
    for i, e in enumerate(entries, 1):
        label = f"aanvaarding #{i} ({e.get('tool')}/{e.get('id')})"
        if e.get("tool") not in TOOLS:
            errors.append(f"{label}: 'tool' moet een van {TOOLS} zijn")
        if not e.get("id"):
            errors.append(f"{label}: 'id' ontbreekt")
        if e.get("verdict") not in VERDICTS:
            errors.append(f"{label}: 'verdict' moet een van {VERDICTS} zijn")
        if len((e.get("reason") or "").strip()) < MIN_REASON_LEN:
            errors.append(f"{label}: 'reason' ontbreekt of is te kort (min. {MIN_REASON_LEN} tekens)")
        k = (e.get("tool"), e.get("id"), e.get("file"), e.get("package"))
        if k in seen:
            errors.append(f"{label}: dubbele aanvaarding")
        seen.add(k)
    return entries, errors


def matches(entry, f):
    if entry.get("tool") != f.tool:
        return False
    if entry.get("id") != f.id and entry.get("id") not in f.alt_ids:
        return False
    for attr in ("file", "package"):
        if entry.get(attr) is not None and entry.get(attr) != f.attrs.get(attr):
            return False
    return True


def snippet(f):
    d = {"tool": f.tool, "id": f.id}
    for attr in ("file", "package"):
        if f.attrs.get(attr):
            d[attr] = f.attrs[attr]
    d.update({"verdict": "echt-probleem | false-positive", "reason": "waarom mag dit nu?"})
    return json.dumps(d, ensure_ascii=False)


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--accepted", default=".security/accepted-findings.json")
    ap.add_argument("--sca", required=True)
    ap.add_argument("--sast", required=True, help="glob naar SARIF-bestanden")
    ap.add_argument("--secrets", required=True)
    ap.add_argument("--tests", help="JSON van security_tests.py (optioneel)")
    ap.add_argument("--container", help="Trivy SARIF bestand (optioneel)")
    ap.add_argument("--min-sast-score", type=float, default=7.0)
    args = ap.parse_args()

    accepted, errors = load_accepted(args.accepted)
    findings = (parse_sca(args.sca)
                + parse_sarif(args.sast, args.min_sast_score)
                + parse_secrets(args.secrets))
    if args.tests:
        findings += parse_tests(args.tests)
    if args.container:
        findings += parse_trivy(args.container)

    new_critical, accepted_hits, other = [], [], []
    used = set()
    for f in findings:
        hit = next((i for i, e in enumerate(accepted) if matches(e, f)), None)
        if hit is not None:
            used.add(hit)
            accepted_hits.append((f, accepted[hit]))
        elif f.critical:
            new_critical.append(f)
        else:
            other.append(f)
    stale = [e for i, e in enumerate(accepted) if i not in used]

    lines = ["## Resultaat van de beveiligingspoort", "",
             "| Scan | Kritiek nieuw | Aanvaard | Niet kritiek |", "|---|---|---|---|"]
    for t in TOOLS:
        lines.append(f"| {t} | {sum(f.tool == t for f in new_critical)} "
                     f"| {sum(f.tool == t for f, _ in accepted_hits)} "
                     f"| {sum(f.tool == t for f in other)} |")
    if new_critical:
        lines += ["", "### Nieuwe kritieke bevindingen (pipeline faalt)", "",
                  "| Scan | Id | Waar | Ernst | Wat |", "|---|---|---|---|---|"]
        lines += [f"| {f.tool} | `{f.id}` | `{f.where()}` | {f.severity} | {f.text} |" for f in new_critical]
        lines += ["", "Is het een echt probleem of een false positive dat nu mag blijven? "
                      "Voeg dan dit toe aan `.security/accepted-findings.json`, met een reden:", "", "```json"]
        lines += [snippet(f) for f in new_critical]
        lines += ["```"]
    if errors:
        lines += ["", "### Ongeldige aanvaardingen (pipeline faalt)", ""] + [f"- {e}" for e in errors]
    if stale:
        lines += ["", "### Aanvaarding zonder bijhorende bevinding (opruimen)", ""]
        lines += [f"- {e.get('tool')}/{e.get('id')}" for e in stale]
    if SKIPPED_TESTS:
        lines += ["", "### Overgeslagen tests (geen bewijs van veiligheid)", "",
                  "De app eist inloggen en de tests hebben nog geen testaccount. Voeg er een toe, "
                  "anders blijven deze eisen ongetest:", ""] + [f"- {t}" for t in SKIPPED_TESTS]
    if accepted_hits:
        lines += ["", "### Aanvaarde bevindingen", "", "| Scan | Id | Verdict | Reden |", "|---|---|---|---|"]
        lines += [f"| {f.tool} | `{f.id}` | {e.get('verdict')} | {e.get('reason')} |" for f, e in accepted_hits]
    report = "\n".join(lines)

    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")

    for f in new_critical:
        print(f"::error title=Nieuwe kritieke bevinding ({f.tool})::{f.id} in {f.where()}")
    if new_critical or errors:
        sys.exit(1)
    print("Geen nieuwe kritieke bevindingen.")


if __name__ == "__main__":
    main()