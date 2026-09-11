# certval_stores_mozilla

The Mozilla root program as a [`certval`](https://github.com/carl-wallace/rust-pki)
trust store, implementing the `TrustStoreProvider` trait from
[`certval_stores_core`](https://github.com/carl-wallace/certval-stores). It is a
sibling of the `certval_stores_*` provider crates rather than a member of that
workspace: the material is public web PKI on Mozilla's release cadence, and it
carries an MPL-2.0 obligation the Federal/DoD providers do not.

172 root certificates, embedded as DER at compile time. No network access, no
build script, no `certdata.txt` parsing at run time.

## What it provides

Three environments, each behind a feature, plus an optional intermediate-CA
store:

| feature | environment | roots | population |
|---|---|---|---|
| `mozilla_tls` (default) | `MOZILLA_TLS` | 121 | the Websites trust bit — TLS server authentication |
| `mozilla_email` | `MOZILLA_EMAIL` | 91 | the Email trust bit — S/MIME |
| `mozilla_all` | `MOZILLA_ALL` | 170 | either trust bit |
| `mozilla_cas` | (adds the CA store to `MOZILLA_ALL`) | — | 2,563 intermediates, 3.9 MB |

```no_run
use certval::{PkiEnvironment, TaSource};
use certval_stores_core::prepare_certval_environment;

let mut pe = PkiEnvironment::default();
pe.populate_5280_pki_environment();
let mut ta_store = TaSource::new();

let providers = [certval_stores_mozilla::provider()];
prepare_certval_environment(&providers, &mut pe, &mut ta_store, "MOZILLA_TLS")?;
# Ok::<(), certval::Error>(())
```

**Roots with no trust bits are not anchors.** Two of the 172 (`Go Daddy Class 2
Certification Authority` and `Starfield Class 2 Certification Authority`) have
every trust bit turned off: NSS still ships them, but Mozilla trusts them for
nothing. They appear in `ROOTS` and in no environment. That is the 172 → 170
gap in the table above.

## The intermediate-CA store

`mozilla_cas` (off by default) embeds a certval `CertSource` — 2,563
CCADB-disclosed intermediates plus the precomputed partial-path graph, 3.9 MB —
and attaches it to `MOZILLA_ALL`.

While it is true that in most web PKI scenarios an intermediate CA is supplied in-band, 
TLS servers sometimes omit them; S/MIME message often carry only the signer certificate, 
and those certificates get reused for client authentication and document signing. 
Validating a certificate *file* is a a pittv3 use case. Without a preloaded store,
those all depend on an AIA fetch, which needs the network and only works when the AIA 
is present and reachable.

CA certificates are only included in `MOZILLA_ALL` because the graph spans all 170 anchors, 
and 85% of it is common to the two purpose-scoped environments. A pruned copy per
environment would roughly triple 3.9 MB to buy very little. It cannot simply be
shared either because the conformance suite requires every serialized path to start at
a CA that the entry's anchors issued, and 356 of these chain only to email-only
roots, so including this graph in `MOZILLA_TLS` would cause those to be reported
as unanchored.

Some artifacts are omitted. `tools/refresh_cas.py` prints every omission
rather than silently truncating:

- **23** disclosed intermediates chain to no trusted root (they hang off the two
  no-trust-bit roots, or off roots Mozilla has removed).

## What it provides that a bare root list does not

`ROOTS` is a table of `MozillaRoot`, not a list of buffers, because two of the
fields are **restrictions Mozilla applies that the certificates do not express**:

- `distrust_for_tls_after` — Mozilla distrusts certificates issued under the
  root with a notBefore after this date while continuing to trust earlier ones.
  Five roots carry one in the current snapshot (four Entrust, one Izenpe). RFC
  5280 path validation cannot see it.
- `mozilla_applied_constraints` — free-text constraints applied outside the
  certificate. Three roots carry one: `*.tr` on a TUBITAK root, and an explicit
  "No name constraints are to be applied" on two Telekom Security S/MIME roots.

`find_by_sha256` is the bridge: hash the anchor certval anchored on, look it up,
and apply the policy yourself. A path that validates under a distrust-after root
is not a path Mozilla would accept if the end entity's notBefore falls after
that date.

These out-of-band constraints are the only ones most of this collection has.
**No root here carries a `nameConstraints` extension at all**, so a relying
party that ignores `mozilla_applied_constraints` is applying no name constraints
to Mozilla's anchors whatsoever. `tests/tests.rs` pins that so a refresh which
changes it fails loudly.

## Provenance

Generated from the CCADB report Mozilla publishes on
[wiki.mozilla.org/CA/Included_Certificates](https://wiki.mozilla.org/CA/Included_Certificates):

```text
https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootCertificateReportPEMCSV
```

The host looks wrong and is not: the CCADB — the Common CA Database, which the
Mozilla CA program administers jointly with the other root programs — runs on
Salesforce, and `ccadb.my.salesforce-sites.com` is its Salesforce Sites domain.
It replaced the older `ccadb-public.secure.force.com`, `force.com` being the
same platform under its retired name. Mozilla's own wiki is what names it.

That is still a report rather than the store, so the material is checked against
the store itself:

```sh
python3 tools/verify_against_nss.py
```

This parses the PKCS #11 built-in object table in **NSS's `certdata.txt`** — what
Firefox actually ships — and compares it to both the CCADB report and the DER
embedded here: same certificates, byte for byte, and the same trust bits derived
from `CKA_TRUST_SERVER_AUTH` / `CKA_TRUST_EMAIL_PROTECTION`. As of the
2026-08-13 snapshot the three agree exactly, with zero disagreements across all
172 certificates. Run it any time to detect drift; CI runs it on a schedule.

## Refreshing

```sh
python3 tools/refresh.py         # roots/mozilla/*.der and src/generated.rs
python3 tools/refresh_cas.py     # cas/mozilla/*.der and cas/mozilla/mozilla.cbor
python3 tools/verify_against_nss.py
cargo test --all-features
```

`refresh_cas.py` needs `certval-store-gen` (RedHoundSoftware) built and on PATH,
or named with `--store-gen`; it must run after `refresh.py`, since it derives the
anchor set from the roots that wrote.

Then update `SNAPSHOT` in `tools/refresh.py`, re-run, and update the
`EXPECTED_*` counts in `tests/tests.rs` to the numbers the two tools print.
`roots/mozilla/` is rewritten from scratch each run, so a root Mozilla removed
does not linger on disk. Requires the `cryptography` Python package; nothing
runs at build time, so consumers need neither Python nor network.

If a refresh is interrupted between writing the directory and writing
`src/generated.rs`, the two can disagree, and only one direction of that shows
up at build time: a missing `.der` breaks `include_bytes!`, while a leftover one
ships looking like a root without being in the table.
`conformance::check_root_inputs` compares the directory against `ROOTS` on every
test run and fails either way. It is checked against `ROOTS` rather than any
environment's anchors because the directory holds the whole published population,
untrusted roots included.

## Size

The 172 root DER files total ~690 KB and are all embedded regardless of which
environment features are on, because `ROOTS` covers the whole snapshot. Feature
selection picks which of them become trust anchors, not which are compiled in —
gating the bytes would save little, since 170 of the 172 are in `MOZILLA_ALL`
anyway.

`mozilla_cas` adds 3.9 MB, which is why it is off by default and why the wasm
and MSRV CI legs build without it. A size-constrained consumer that only wants
TLS anchors and can live without the metadata should take
`certval::TaSource::new_from_webpki` instead.

## License

MPL-2.0, following the Mozilla CA certificate data it embeds.
