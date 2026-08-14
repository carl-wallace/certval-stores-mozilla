#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Cross-check the embedded material against NSS's own certdata.txt.

`tools/refresh.py` generates this crate from a CCADB report. CCADB is the
database the Mozilla CA program administers, but it is a *rendering* of the
store rather than the store: what Firefox actually ships is the PKCS #11
built-in object table in `certdata.txt`, in the NSS source tree. This checks one
against the other — same certificates, byte for byte, and the same trust bits —
so the provenance of the embedded roots does not rest on trusting a report URL.

    python3 tools/verify_against_nss.py

Exits non-zero on any disagreement. Needs network access to raw.githubusercontent.com
(the NSS mirror) and to CCADB; pass a local certdata.txt path as the first
argument to skip the former.
"""

import csv
import hashlib
import io
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from refresh import REPORT_URL, ROOTS_DIR, fetch  # noqa: E402

CERTDATA_URL = (
    "https://raw.githubusercontent.com/nss-dev/nss/master/lib/ckfw/builtins/certdata.txt"
)
# NSS's "trust this CA to issue for this purpose"; anything else (notably
# CKT_NSS_MUST_VERIFY_TRUST) is not a trust bit.
TRUSTED = "CKT_NSS_TRUSTED_DELEGATOR"


def parse_certdata(text):
    """Parse certdata.txt into a list of PKCS #11 object dicts.

    The format is a flat stream of `CKA_<attr> <type> <value>` lines, one object
    starting at each CKA_CLASS line, with DER carried as MULTILINE_OCTAL blocks
    of `\\ooo` escapes terminated by END.
    """
    objs, cur, multi, key = [], None, None, None
    for line in text.splitlines():
        if multi is not None:
            if line.strip() == "END":
                cur[key] = bytes(int(o, 8) for o in re.findall(r"\\([0-7]{3})", multi))
                multi, key = None, None
            else:
                multi += line
            continue
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith("CKA_CLASS "):
            if cur:
                objs.append(cur)
            cur = {"CKA_CLASS": line.split()[-1]}
            continue
        if cur is None:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        attr, kind = parts[0], parts[1]
        if kind == "MULTILINE_OCTAL":
            key, multi = attr, ""
        else:
            cur[attr] = (parts[2] if len(parts) > 2 else "").strip().strip('"')
    if cur:
        objs.append(cur)
    return objs


def nss_store(text):
    """{sha256 -> {label, der, websites, email}} from certdata.txt.

    Certificates and their trust settings are separate objects, joined by label.
    """
    objs = parse_certdata(text)
    trusts = {o["CKA_LABEL"]: o for o in objs if o["CKA_CLASS"] == "CKO_NSS_TRUST"}
    store = {}
    for o in objs:
        if o["CKA_CLASS"] != "CKO_CERTIFICATE":
            continue
        trust = trusts.get(o["CKA_LABEL"], {})
        store[hashlib.sha256(o["CKA_VALUE"]).hexdigest().upper()] = {
            "label": o["CKA_LABEL"],
            "der": o["CKA_VALUE"],
            "websites": trust.get("CKA_TRUST_SERVER_AUTH") == TRUSTED,
            "email": trust.get("CKA_TRUST_EMAIL_PROTECTION") == TRUSTED,
        }
    return store


def ccadb_store(text):
    """{sha256 -> {name, websites, email}} from the CCADB PEM CSV report."""
    store = {}
    for row in csv.DictReader(io.StringIO(text)):
        bits = [b.strip() for b in row["Trust Bits"].split(";") if b.strip()]
        store[row["SHA-256 Fingerprint"].strip().upper()] = {
            "name": row["Common Name or Certificate Name"],
            "websites": "Websites" in bits,
            "email": "Email" in bits,
        }
    return store


def embedded_store():
    """{sha256 -> (filename, der)} for the DER files this crate embeds."""
    store = {}
    for filename in sorted(os.listdir(ROOTS_DIR)):
        if not filename.endswith(".der"):
            continue
        with open(os.path.join(ROOTS_DIR, filename), "rb") as f:
            der = f.read()
        store[hashlib.sha256(der).hexdigest().upper()] = (filename, der)
    return store


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
            certdata = f.read()
    else:
        certdata = fetch(CERTDATA_URL).decode("utf-8", errors="replace")

    nss = nss_store(certdata)
    # fetch() takes a local path from argv[1]; call the URL form directly here.
    ccadb = ccadb_store(
        subprocess.run(
            ["curl", "-sSfL", "--retry", "3", "--retry-all-errors", REPORT_URL],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout.decode("utf-8-sig")
    )
    embedded = embedded_store()

    print(f"NSS certdata.txt : {len(nss)} certificates")
    print(f"CCADB report     : {len(ccadb)} certificates")
    print(f"embedded in crate: {len(embedded)} certificates\n")

    failures = []
    for label, store in (("CCADB report", ccadb), ("embedded material", embedded)):
        for fingerprint in set(store) - set(nss):
            failures.append(f"{label} carries {fingerprint}, which NSS does not")
        for fingerprint in set(nss) - set(store):
            failures.append(
                f"NSS carries {nss[fingerprint]['label']} ({fingerprint}), which the {label} does not"
            )

    for fingerprint in set(embedded) & set(nss):
        if embedded[fingerprint][1] != nss[fingerprint]["der"]:
            failures.append(
                f"{embedded[fingerprint][0]} differs byte-for-byte from NSS despite matching fingerprints"
            )

    for fingerprint in set(ccadb) & set(nss):
        c, n = ccadb[fingerprint], nss[fingerprint]
        if (c["websites"], c["email"]) != (n["websites"], n["email"]):
            failures.append(
                f"{c['name']}: CCADB says websites={c['websites']} email={c['email']}, "
                f"NSS says websites={n['websites']} email={n['email']}"
            )

    if failures:
        print(f"{len(failures)} disagreement(s):")
        for f in failures:
            print(f"  - {f}")
        return 1

    tls = sum(1 for v in nss.values() if v["websites"])
    email = sum(1 for v in nss.values() if v["email"])
    neither = sum(1 for v in nss.values() if not v["websites"] and not v["email"])
    print("OK — CCADB, NSS, and the embedded DER agree on every certificate and trust bit.")
    print(f"  websites={tls}  email={email}  no trust bits={neither}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
