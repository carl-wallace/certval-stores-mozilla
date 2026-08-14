#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Refresh the embedded Mozilla trust material from CCADB.

Downloads Mozilla's included-CA report, writes one DER file per root under
`roots/mozilla/`, and regenerates `src/generated.rs`. Run from anywhere:

    python3 tools/refresh.py

Requires the `cryptography` package (used only to convert PEM to DER and to
confirm each row's published fingerprint matches the certificate it carries).
Nothing here runs at build time: the generated file and the DER files are
committed, so consumers need no Python and no network.

After running, update `SNAPSHOT` below, re-run, and check the counts the tests
assert (`tests/tests.rs`) against what this prints.
"""

import csv
import hashlib
import io
import os
import re
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

# The URL Mozilla itself publishes on https://wiki.mozilla.org/CA/Included_Certificates.
# The odd-looking host is Salesforce: the CCADB runs on Salesforce's platform, and
# `ccadb.my.salesforce-sites.com` is its Sites domain (it replaced the older
# `ccadb-public.secure.force.com`, force.com being the same platform's retired name).
# The data is not taken on faith — tools/verify_against_nss.py checks this report
# against NSS's own certdata.txt, which is what Firefox actually ships.
REPORT_URL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootCertificateReportPEMCSV"
# Date this snapshot was taken, in the generated SNAPSHOT_DATE constant.
SNAPSHOT = "2026-08-13"

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOTS_DIR = os.path.join(REPO, "roots", "mozilla")
GENERATED = os.path.join(REPO, "src", "generated.rs")


def slug(name):
    """A stable, filesystem-safe file stem derived from the certificate name."""
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")[:80]


def iso(date):
    """CCADB publishes dates as YYYY.MM.DD; emit ISO 8601 calendar dates."""
    date = date.strip()
    return date.replace(".", "-") if date else ""


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_opt(s):
    return f"Some({rust_str(s)})" if s else "None"


def fetch(url, local=None):
    """Bytes of `url`, or of `local` when given — the other tools in this folder
    import this, so the local override is an argument rather than something read
    out of sys.argv behind their backs."""
    if local:  # a local copy, for reproducing a past snapshot
        with open(local, "rb") as f:
            return f.read()
    # curl rather than urllib: the CCADB endpoint serves this report with
    # chunked transfer encoding and closes short often enough that urllib raises
    # IncompleteRead mid-download. curl retries and fails loudly on a partial
    # body, which matters here — a truncated CSV would silently drop roots.
    return subprocess.run(
        ["curl", "-sSfL", "--retry", "3", "--retry-all-errors", url],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def main():
    raw = fetch(REPORT_URL, sys.argv[1] if len(sys.argv) > 1 else None)
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    print(f"{len(rows)} rows from {REPORT_URL}")

    # Clear the .der files, and only those, so a root Mozilla *removed* does not
    # linger on disk. Deliberately not a recursive delete of ROOTS_DIR: this
    # path comes from __file__ and would follow a moved or symlinked checkout.
    os.makedirs(ROOTS_DIR, exist_ok=True)
    for stale in os.listdir(ROOTS_DIR):
        if stale.endswith(".der"):
            os.remove(os.path.join(ROOTS_DIR, stale))

    roots, stems = [], {}
    for row in rows:
        pem = row["PEM Info"].strip().strip("'")
        cert = x509.load_pem_x509_certificate(pem.encode())
        der = cert.public_bytes(Encoding.DER)

        fingerprint = hashlib.sha256(der).hexdigest().upper()
        published = row["SHA-256 Fingerprint"].strip().upper()
        if fingerprint != published:
            raise SystemExit(
                f"{row['Common Name or Certificate Name']}: PEM hashes to "
                f"{fingerprint}, report says {published}"
            )

        stem = slug(row["Common Name or Certificate Name"])
        n = stems.get(stem, 0)
        stems[stem] = n + 1
        filename = f"{stem}.der" if n == 0 else f"{stem}_{n}.der"
        with open(os.path.join(ROOTS_DIR, filename), "wb") as f:
            f.write(der)

        bits = [b.strip() for b in row["Trust Bits"].split(";") if b.strip()]
        roots.append(
            {
                "filename": filename,
                "cn": row["Common Name or Certificate Name"],
                "owner": row["Owner"],
                "sha256": fingerprint,
                "websites": "Websites" in bits,
                "email": "Email" in bits,
                "not_before": iso(row["Valid From [GMT]"]),
                "not_after": iso(row["Valid To [GMT]"]),
                "key_alg": row["Public Key Algorithm"].strip(),
                "distrust_tls": iso(row["Distrust for TLS After Date"]),
                "distrust_smime": iso(row["Distrust for S/MIME After Date"]),
                "constraints": row["Mozilla Applied Constraints"].strip(),
            }
        )

    roots.sort(key=lambda r: (r["cn"].lower(), r["sha256"]))

    tls = [i for i, r in enumerate(roots) if r["websites"]]
    email = [i for i, r in enumerate(roots) if r["email"]]
    both = [i for i, r in enumerate(roots) if r["websites"] or r["email"]]

    out = []
    w = out.append
    w("// @generated by tools/refresh.py — do not edit by hand.")
    w(f"// Source: {REPORT_URL}")
    w(f"// Snapshot: {SNAPSHOT} ({len(roots)} included roots)")
    # Re-emitted on every refresh: this file embeds MPL-2.0 material, and a
    # regeneration that dropped the notice would silently strip it.
    w("//")
    w("// This Source Code Form is subject to the terms of the Mozilla Public")
    w("// License, v. 2.0. If a copy of the MPL was not distributed with this")
    w("// file, You can obtain one at https://mozilla.org/MPL/2.0/.")
    w("")
    w("use crate::MozillaRoot;")
    w("")
    w("/// The CCADB report this material was generated from.")
    w(f"pub const CCADB_REPORT_URL: &str = {rust_str(REPORT_URL)};")
    w("")
    w("/// Date the embedded snapshot was taken, ISO 8601.")
    w(f"pub const SNAPSHOT_DATE: &str = {rust_str(SNAPSHOT)};")
    w("")
    for i, r in enumerate(roots):
        w(f"const DER_{i}: &[u8] = include_bytes!({rust_str('../roots/mozilla/' + r['filename'])});")
    w("")
    w("/// Every root in the snapshot, in case-insensitive name order, with the")
    w("/// metadata CCADB publishes beside it. Includes roots carrying no trust")
    w("/// bits at all, which the environment slices below deliberately omit.")
    w("pub static ROOTS: &[MozillaRoot] = &[")
    for i, r in enumerate(roots):
        w("    MozillaRoot {")
        w(f"        der: DER_{i},")
        w(f"        common_name: {rust_str(r['cn'])},")
        w(f"        owner: {rust_str(r['owner'])},")
        w(f"        sha256_fingerprint: {rust_str(r['sha256'])},")
        w(f"        websites: {str(r['websites']).lower()},")
        w(f"        email: {str(r['email']).lower()},")
        w(f"        not_before: {rust_str(r['not_before'])},")
        w(f"        not_after: {rust_str(r['not_after'])},")
        w(f"        public_key_algorithm: {rust_str(r['key_alg'])},")
        w(f"        distrust_for_tls_after: {rust_opt(r['distrust_tls'])},")
        w(f"        distrust_for_smime_after: {rust_opt(r['distrust_smime'])},")
        w(f"        mozilla_applied_constraints: {rust_opt(r['constraints'])},")
        w("    },")
    w("];")
    w("")

    for name, idx, doc in [
        ("TLS_ROOTS", tls, "the Websites trust bit"),
        ("EMAIL_ROOTS", email, "the Email trust bit"),
        ("ALL_ROOTS", both, "either trust bit"),
    ]:
        w(f"/// DER of every root carrying {doc} ({len(idx)} of {len(roots)}).")
        w(f"pub static {name}: &[&[u8]] = &[")
        for i in idx:
            w(f"    DER_{i},")
        w("];")
        w("")

    with open(GENERATED, "w") as f:
        f.write("\n".join(out).rstrip("\n") + "\n")

    # The generated file is checked by `cargo fmt --all --check` in CI like any
    # other source file, and a few of the longer certificate names push their
    # lines past the width rustfmt wants. Formatting here rather than teaching
    # the emitter to wrap keeps the emitter readable.
    try:
        subprocess.run(["rustfmt", "--edition", "2021", GENERATED], check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"warning: could not run rustfmt on {GENERATED}: {e}", file=sys.stderr)

    print(f"wrote {len(roots)} DER files to {ROOTS_DIR}")
    print(f"wrote {GENERATED}")
    print(f"  TLS_ROOTS   = {len(tls)}")
    print(f"  EMAIL_ROOTS = {len(email)}")
    print(f"  ALL_ROOTS   = {len(both)}")
    print(f"  no trust bits (omitted from every slice) = {len(roots) - len(both)}")
    for r in roots:
        if not r["websites"] and not r["email"]:
            print(f"    - {r['cn']}")


if __name__ == "__main__":
    main()
