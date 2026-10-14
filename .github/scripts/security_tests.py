#!/usr/bin/env python3
"""Beveiligingstests op het GEDRAG van de draaiende app.

Statische scans zien codepatronen, maar geen autorisatiefouten: of iemand een bericht
van een ander mag lezen of verwijderen, hangt af van wat de app doet, niet van hoe de
code eruitziet. Daarom start de pipeline de app en probeert dit script het misbruik echt.

Elke test beschrijft een beveiligingseis. Gedraagt de app zich anders dan de eis, dan
is dat een bevinding. De bevindingen gaan als JSON naar de poort (security_gate.py),
die ze net zo behandelt als de andere scans: nieuwe bevindingen laten de pipeline
falen, aanvaarde (met reden) niet.

Het script faalt gesloten: start de app niet of lukt een voorbereiding niet door een
fout (en niet doordat de app terecht weigert), dan stopt het met exitcode 2.

Enkel standaardbibliotheek.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def call(base, method, path, user=None, body=None):
    headers = {}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if user:
        headers["X-User"] = user
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def fail_closed(msg):
    print(f"::error::{msg}")
    sys.exit(2)


def wait_healthy(base):
    for _ in range(60):
        try:
            status, body = call(base, "GET", "/health")
            if status == 200 and body.strip() == "ok":
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(2)
    fail_closed(f"De app werd niet gezond op {base}/health: de tests konden niet draaien")


def create_message(base, sender, recipient):
    """Maakt een testbericht. Geeft het id terug, of None als de app terecht weigert."""
    status, body = call(base, "POST", "/api/messages", user=sender, body={
        "sender": sender, "recipient": recipient,
        "subject": "beveiligingstest", "body": "testbericht, mag verwijderd worden",
    })
    if status in (401, 403):
        return None
    if status not in (200, 201):
        fail_closed(f"Voorbereiding mislukt: POST /api/messages gaf {status}")
    try:
        return json.loads(body)["id"]
    except (ValueError, KeyError, TypeError):
        fail_closed("Voorbereiding mislukt: geen id in het antwoord van POST /api/messages")


def run_tests(base):
    findings, skipped = [], []

    def finding(fid, endpoint, title, expected, actual):
        findings.append({"id": fid, "endpoint": endpoint, "title": title,
                         "expected": expected, "actual": str(actual), "severity": "high"})

    # 1. Identiteit zonder bewijs (X-User-header)
    status, _ = call(base, "GET", "/api/messages", user="tester-b")
    if status == 200:
        finding("identity-without-credential", "GET /api/messages",
                "Iedereen kan zich voordoen als een willekeurige gebruiker door een header mee te sturen",
                "401 of 403 zonder wachtwoord of token", status)

    # 2. Bericht van een ander lezen
    mid = create_message(base, "tester-a", "tester-b")
    if mid is None:
        skipped.append("idor-read-foreign-message")
    else:
        status, _ = call(base, "GET", f"/api/messages/{mid}", user="tester-c")
        if status == 200:
            finding("idor-read-foreign-message", "GET /api/messages/{id}",
                    "Een derde die geen afzender of ontvanger is, kan het bericht lezen",
                    "403 of 404", status)

    # 3. Verwijderen zonder identiteit
    mid = create_message(base, "tester-a", "tester-b")
    if mid is None:
        skipped.append("delete-without-identity")
    else:
        status, _ = call(base, "DELETE", f"/api/messages/{mid}")
        if status in (200, 204):
            finding("delete-without-identity", "DELETE /api/messages/{id}",
                    "Een bericht kan verwijderd worden zonder dat de aanvrager zich bekendmaakt",
                    "401 of 403", status)

    # 4. Bericht van een ander verwijderen
    mid = create_message(base, "tester-a", "tester-b")
    if mid is None:
        skipped.append("delete-foreign-message")
    else:
        status, _ = call(base, "DELETE", f"/api/messages/{mid}", user="tester-c")
        if status in (200, 204):
            finding("delete-foreign-message", "DELETE /api/messages/{id}",
                    "Een derde die geen afzender of ontvanger is, kan het bericht verwijderen",
                    "403 of 404", status)

    return findings, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--output", default="tests.json")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    wait_healthy(base)
    findings, skipped = run_tests(base)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"base_url": base, "findings": findings, "skipped": skipped}, fh, indent=2)

    for f in findings:
        print(f"BEVINDING {f['id']}: {f['title']} (verwacht {f['expected']}, kreeg {f['actual']})")
    for s in skipped:
        print(f"OVERGESLAGEN {s}: de app eist inloggen en dit script heeft nog geen testaccount")
    print(f"{len(findings)} bevinding(en), {len(skipped)} overgeslagen")


if __name__ == "__main__":
    main()