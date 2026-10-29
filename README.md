# certval_stores_mozilla

The Mozilla root program as a [`certval`](https://github.com/carl-wallace/rust-pki)
trust store, implementing the `TrustStoreProvider` trait from
[`certval_stores_provider_core`](https://github.com/carl-wallace/certval-stores). It is a
sibling of the `certval_stores_*` provider crates rather than a member of that
workspace: the material is public web PKI on Mozilla's release cadence, and it
carries an MPL-2.0 obligation the Federal/DoD providers do not.

Mozilla's root certificates, embedded as DER at compile time. No network access, no
build script, no `certdata.txt` parsing at run time.

## What it provides

Three environments, each behind a feature, plus an optional intermediate-CA
store:

| feature | constant (id) | roots | population |
|---|---|---|---|
| `mozilla_tls` (default) | `MOZILLA_TLS` (`mozilla_tls`) | the Websites trust bit — TLS server authentication |
| `mozilla_email` | `MOZILLA_EMAIL` (`mozilla_email`) | the Email trust bit — S/MIME |
| `mozilla_all` | `MOZILLA_ALL` (`mozilla_all`) | either trust bit |
| `mozilla_cas` | (adds the CA store to `MOZILLA_ALL`) | the CCADB-disclosed intermediates, several megabytes |

```rust
# #[cfg(feature = "mozilla_tls")] {
use certval::PkiEnvironment;
use certval_stores_core::prepare_certval_environment;

let mut pe = PkiEnvironment::default();
pe.populate_5280_pki_environment();
let providers = [certval_stores_mozilla::provider()];
prepare_certval_environment(&providers, &mut pe, certval_stores_mozilla::MOZILLA_TLS)?;
# }
# Ok::<(), certval::Error>(())
```

**Roots with no trust bits are not anchors.** Some roots (`Go Daddy Class 2
Certification Authority` and `Starfield Class 2 Certification Authority` today)
have every trust bit turned off: NSS still ships them, but Mozilla trusts them
for nothing. They appear in `ROOTS` and in no environment.

## The intermediate-CA store

`mozilla_cas` (off by default) embeds a certval `CertSource` — the
CCADB-disclosed intermediates plus the precomputed partial-path graph, several
megabytes — and attaches it to `MOZILLA_ALL`.

While it is true that in most web PKI scenarios an intermediate CA is supplied in-band, 
TLS servers sometimes omit them; S/MIME message often carry only the signer certificate, 
and those certificates get reused for client authentication and document signing. 
Validating a certificate *file* is a a pittv3 use case. Without a preloaded store,
those all depend on an AIA fetch, which needs the network and only works when the AIA 
is present and reachable.

CA certificates are only included in `MOZILLA_ALL` because the graph spans all the anchors,
and most of it is common to the two purpose-scoped environments. A pruned copy per
environment would roughly triple the store's size to buy very little. It cannot simply be
shared either because the conformance suite requires every serialized path to start at
a CA that the entry's anchors issued, and many of these chain only to email-only
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

**CCADB is the authoritative source.** The roots, their trust bits and their
distrust dates come from its report. NSS's `certdata.txt`, the built-in object
table Firefox ships, serves as a consistency check rather than a second source:

```sh
python3 tools/verify_against_nss.py
```

This compares NSS's certificates with the certificates embedded here, byte for
byte, and NSS's trust bits (`CKA_TRUST_SERVER_AUTH` /
`CKA_TRUST_EMAIL_PROTECTION`) with the trust bits in the CCADB report. CCADB
records a Mozilla decision before NSS carries it, so the two can disagree for a
while after a change; when they do, this crate follows CCADB, and the check
reports the disagreement for a person to look at. On 2026-10-28 they agreed on every certificate and every trust bit. CI runs the check on a schedule.

## Versioning

This crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the version
number also says what changed in the trust material:

- A **patch** release (1.0.0 to 1.0.1) changes intermediate CA certificates, partial paths, or a
  store's dates or label. No store's trust anchors change.
- A **minor** release (1.0.x to 1.1.0) adds or removes trust anchors in a store, adds a store, or
  adds to the API without breaking code that uses it.
- A **major** release (1.x to 2.0.0) changes the API in a way that breaks code that uses it, for
  example by removing a store along with its feature and constant.

With an ordinary requirement such as `certval_stores_mozilla = "1.0"`, `cargo update` takes every
1.x release, including a minor release that adds or removes trust anchors. With
`certval_stores_mozilla = "~1.0"`, `cargo update` takes 1.0.1, 1.0.2 and so on, which change only
intermediate CA certificates, partial paths or dates, and does not take 1.1.0, so the trust anchors
stay those of 1.0 until the requirement is changed to `~1.1`. Each release's changes are listed in
`CHANGELOG.md`.

## Refreshing

```sh
python3 tools/refresh.py         # roots/mozilla/*.der and src/generated.rs
python3 tools/refresh_cas.py     # cas/mozilla/*.der and cas/mozilla/mozilla.cbor
python3 tools/verify_against_nss.py
cargo test --all-features
```

`refresh_cas.py` needs `certval-store-gen` (from `carl-wallace/certval-stores`) built and on PATH,
or named with `--store-gen`; it must run after `refresh.py`, since it derives the
anchor set from the roots that wrote.

Then update `SNAPSHOT` in `tools/refresh.py`, re-run, and update the pinned
counts and set digests in `tests/tests.rs` with `UPDATE_PINS=1 cargo test --all-features`,
then `cargo fmt`, a plain `cargo test --all-features`, and a read of the diff.
`SNAPSHOT` is also what every `StoreEntry` reports as its collection date, so a
refresh that leaves it alone tells consumers the material is older than it is;
the entries report no publication date, the CCADB report being a live query
rather than a dated release.
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

The root DER files total under a megabyte and are all embedded regardless of which
environment features are on, because `ROOTS` covers the whole snapshot. Feature
selection picks which of them become trust anchors, not which are compiled in —
gating the bytes would save little, since nearly all of them are in `MOZILLA_ALL`
anyway.

`mozilla_cas` adds several megabytes, which is why it is off by default and why the wasm
and MSRV CI legs build without it. A size-constrained consumer that only wants
TLS anchors and can live without the metadata should take
`certval::TaSource::new_from_webpki` instead.

## License

MPL-2.0, following the Mozilla CA certificate data it embeds.
