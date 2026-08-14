#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Refresh the embedded intermediate-CA store from CCADB.

`tools/refresh.py` handles the anchors. This handles the CAs beneath them: it
downloads every intermediate CCADB discloses under the Mozilla program, keeps
those that actually chain to an embedded root, writes them to `cas/mozilla/`,
and drives `certval-store-gen` to build the CBOR `CertSource` — buffers plus the
precomputed partial-path graph — that the `mozilla_cas` feature embeds.

    python3 tools/refresh_cas.py [--store-gen /path/to/certval-store-gen]

`certval-store-gen` (RedHoundSoftware/certval-store-gen) must be built and
either on PATH or named with `--store-gen`. Requires the `cryptography` package.
Nothing runs at build time; the generated store is committed.

Two reports are pulled, because neither is a superset of the other: the
"all intermediates" disclosure report, and the CRL-oriented report, which is the
only one carrying the technically-constrained sub-CAs.
"""

import argparse
import collections
import csv
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

import warnings

warnings.filterwarnings("ignore")  # CCADB carries certs with non-positive serials

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from refresh import REPO, REPORT_URL, ROOTS_DIR, fetch  # noqa: E402

INTERMEDIATE_REPORTS = [
    (
        "https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV",
        "PEM Info",
    ),
    (
        "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport",
        "PEM",
    ),
]

CAS_DIR = os.path.join(REPO, "cas", "mozilla")
STORE = os.path.join(CAS_DIR, "mozilla.cbor")


def fingerprint(der):
    return hashlib.sha256(der).hexdigest().upper()


def load_report(url, pem_column):
    """{sha256 -> certificate} from a CCADB CSV report carrying PEM."""
    out = {}
    for row in csv.DictReader(io.StringIO(fetch(url).decode("utf-8-sig"))):
        pem = (row.get(pem_column) or "").strip().strip("'")
        if not pem:
            continue
        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except Exception:
            continue
        out.setdefault(fingerprint(cert.public_bytes(Encoding.DER)), cert)
    return out


def trusted_roots():
    """{sha256 -> certificate} for the anchors of the MOZILLA_ALL environment.

    The two roots with every trust bit turned off are excluded, because that is
    the anchor set the store hangs off: include them and the graph acquires
    paths headed by CAs those roots issued (the Go Daddy / Starfield G2
    cross-certificates), which the conformance suite correctly reports as
    unanchored for an entry that does not carry them.
    """
    trust_bits = {}
    for row in csv.DictReader(io.StringIO(fetch(REPORT_URL).decode("utf-8-sig"))):
        bits = [b.strip() for b in row["Trust Bits"].split(";") if b.strip()]
        trust_bits[row["SHA-256 Fingerprint"].strip().upper()] = (
            "Websites" in bits or "Email" in bits
        )

    out, untrusted = {}, 0
    for filename in sorted(os.listdir(ROOTS_DIR)):
        if not filename.endswith(".der"):
            continue
        with open(os.path.join(ROOTS_DIR, filename), "rb") as f:
            der = f.read()
        fp = fingerprint(der)
        if trust_bits.get(fp):
            out[fp] = x509.load_der_x509_certificate(der)
        else:
            untrusted += 1
    print(f"{len(out)} trusted anchors ({untrusted} with no trust bits, excluded)")
    return out


def self_signed(cert):
    """Whether `cert`'s signature verifies under its own public key."""
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:
        return False


def reachable(roots, intermediates):
    """Intermediates transitively issued by `roots`, by verified signature.

    Breadth-first from the anchors, following issuer name to candidate children
    and confirming each edge cryptographically — the same edges certval's
    find_all_partial_paths will find, so the store does not ship CAs the path
    builder can never reach.
    """
    by_issuer = collections.defaultdict(list)
    for fp, cert in intermediates.items():
        by_issuer[cert.issuer.public_bytes()].append(fp)

    frontier = list(roots.values())
    seen = set()
    while frontier:
        following = []
        for issuer in frontier:
            for fp in by_issuer.get(issuer.subject.public_bytes(), ()):
                if fp in seen:
                    continue
                child = intermediates[fp]
                try:
                    child.verify_directly_issued_by(issuer)
                except Exception:
                    continue
                seen.add(fp)
                following.append(child)
        frontier = following
    return seen


def store_contents(path):
    """(all fingerprints, fingerprints appearing in some partial path).

    A buffer in no partial path is one the path builder will never reach — dead
    weight the conformance suite reports — so the two sets are what the
    generation loop below reconciles.
    """
    import cbor2

    with open(path, "rb") as f:
        store = cbor2.load(f)
    buffers = [fingerprint(bytes(b["bytes"])) for b in store["buffers"]]
    reached = set()
    for row in store["partial_paths"]:
        for paths in row.values():
            for path_indices in paths:
                for i in path_indices:
                    if i < len(buffers):
                        reached.add(buffers[i])
    return set(buffers), reached


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--store-gen",
        default=shutil.which("certval-store-gen"),
        help="path to the certval-store-gen binary (default: from PATH)",
    )
    args = parser.parse_args()
    if not args.store_gen:
        raise SystemExit(
            "certval-store-gen not found on PATH; build it and pass --store-gen"
        )

    roots = trusted_roots()

    intermediates = {}
    for url, column in INTERMEDIATE_REPORTS:
        report = load_report(url, column)
        new = sum(1 for fp in report if fp not in intermediates)
        for fp, cert in report.items():
            intermediates.setdefault(fp, cert)
        print(f"  {len(report):5} from {url.rsplit('/', 1)[-1]} ({new} new)")

    # A certificate that is also an anchor is not an intermediate, and neither is
    # a self-signed one. certval's `cert_folder_to_vec` — which is what reads
    # cas/mozilla/ on the way into the store — calls `is_self_signed_with_buffer`
    # and skips anything self-signed, so a self-signed certificate left here
    # would be a file with no counterpart in the store, which the conformance
    # suite reads as drift.
    #
    # The test is a verified self-signature, not `subject == issuer`, and the
    # difference matters: a key-rollover certificate is self-*issued* but signed
    # under the CA's other key, and it is a legitimate intermediate that certval
    # keeps. Matching certval's test here keeps those.
    for fp in list(intermediates):
        cert = intermediates[fp]
        if fp in roots or self_signed(cert):
            del intermediates[fp]
    print(f"{len(intermediates)} unique intermediates after removing anchors and self-signed")

    keep = reachable(roots, intermediates)
    dropped = sorted(set(intermediates) - keep)
    print(f"{len(keep)} chain to an embedded root; {len(dropped)} do not and are omitted:")
    for fp in dropped:
        print(f"  - {intermediates[fp].subject.rfc4514_string()[:90]}")

    os.makedirs(CAS_DIR, exist_ok=True)
    for stale in os.listdir(CAS_DIR):
        if stale.endswith(".der"):
            os.remove(os.path.join(CAS_DIR, stale))
    for fp in sorted(keep):
        with open(os.path.join(CAS_DIR, f"{fp}.der"), "wb") as f:
            f.write(intermediates[fp].public_bytes(Encoding.DER))

    # certval-store-gen wants the anchors as a folder so it can register them
    # before building the graph; it writes ta.cbor beside ca.cbor and only the
    # latter is embedded (the anchors ship as individual DER, from refresh.py).
    #
    # Generation runs to a fixed point rather than once. Reachability above is
    # computed the way this script can — issuer name plus a verified signature —
    # but certval decides what actually enters the graph, and it declines more
    # than that: a certificate x509-cert cannot decode, or one whose signature
    # algorithm certval cannot verify, ends up a buffer in no partial path. That
    # is dead weight the conformance suite reports, so anything certval did not
    # reach is dropped and the store rebuilt without it. Each pass names what it
    # removed; a store that silently shed CAs would look complete and not be.
    with tempfile.TemporaryDirectory() as tmp:
        ta_dir = os.path.join(tmp, "tas")
        os.makedirs(ta_dir)
        for fp, cert in roots.items():
            with open(os.path.join(ta_dir, f"{fp}.der"), "wb") as f:
                f.write(cert.public_bytes(Encoding.DER))

        for attempt in range(1, 6):
            out = os.path.join(tmp, f"out{attempt}")
            subprocess.run(
                [args.store_gen, "--out-dir", out, "local", "--tas", ta_dir, "--cas", CAS_DIR],
                check=True,
            )
            shutil.copyfile(os.path.join(out, "ca.cbor"), STORE)

            in_store, reached = store_contents(STORE)
            unreached = set()
            for filename in sorted(os.listdir(CAS_DIR)):
                if not filename.endswith(".der"):
                    continue
                fp = filename[:-4]
                if fp not in in_store or fp not in reached:
                    unreached.add(fp)
                    os.remove(os.path.join(CAS_DIR, filename))
            if not unreached:
                break
            print(f"\npass {attempt}: certval reached no path for {len(unreached)}; removed:")
            for fp in sorted(unreached):
                cert = intermediates[fp]
                print(
                    f"  - {cert.subject.rfc4514_string()[:80]}"
                    f"  [{cert.signature_algorithm_oid._name}]"
                )
        else:
            raise SystemExit("store did not converge in 5 passes")

    print(f"\nwrote {STORE} ({os.path.getsize(STORE) / 1e6:.2f} MB)")
    print(f"  intermediates in store: {len(in_store)}")
    print("update EXPECTED_INTERMEDIATES in tests/tests.rs to match")


if __name__ == "__main__":
    main()
