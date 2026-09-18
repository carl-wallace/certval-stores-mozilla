// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests for the Mozilla provider.
//!
//! The shared checks in `certval_stores_core::conformance` cover what every
//! provider owes its consumers — parseable anchors, usable key identifiers, an
//! environment `prepare_certval_environment` accepts. What is specific to this
//! provider, and covered here, is that the *population* is the one CCADB
//! published: the counts below are the contract between `tools/refresh.py` and
//! this crate, and they are expected to change with each refresh.

use std::collections::BTreeSet;

use certval::{Error, PkiEnvironment, TaSource};
use certval_stores_core::{conformance, prepare_certval_environment, TrustStoreProvider};
use certval_stores_mozilla::{find_by_sha256, ALL_ROOTS, EMAIL_ROOTS, PROVIDER, ROOTS, TLS_ROOTS};

/// Counts from the embedded snapshot. Update these with the material; run
/// `python3 tools/refresh.py` and use the numbers it prints.
const EXPECTED_ROOTS: usize = 172;
const EXPECTED_TLS: usize = 121;
const EXPECTED_EMAIL: usize = 91;
const EXPECTED_ALL: usize = 170;
/// Intermediates in the `mozilla_cas` store; `tools/refresh_cas.py` prints it.
#[cfg(feature = "mozilla_cas")]
const EXPECTED_INTERMEDIATES: usize = 2563;

fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![certval_stores_mozilla::provider()]
}

#[test]
fn provider_is_conformant() {
    conformance::assert_conformant(certval_stores_mozilla::provider());
}

#[test]
fn snapshot_carries_the_expected_population() {
    assert_eq!(ROOTS.len(), EXPECTED_ROOTS);
    assert_eq!(TLS_ROOTS.len(), EXPECTED_TLS);
    assert_eq!(EMAIL_ROOTS.len(), EXPECTED_EMAIL);
    assert_eq!(ALL_ROOTS.len(), EXPECTED_ALL);
}

/// The metadata table and the DER slices are generated from one another, so a
/// divergence means the generator was interrupted or the file hand-edited.
#[test]
fn slices_agree_with_the_metadata_table() {
    let tls: BTreeSet<&[u8]> = ROOTS.iter().filter(|r| r.websites).map(|r| r.der).collect();
    let email: BTreeSet<&[u8]> = ROOTS.iter().filter(|r| r.email).map(|r| r.der).collect();
    let all: BTreeSet<&[u8]> = ROOTS
        .iter()
        .filter(|r| r.is_trusted())
        .map(|r| r.der)
        .collect();

    assert_eq!(tls, TLS_ROOTS.iter().copied().collect());
    assert_eq!(email, EMAIL_ROOTS.iter().copied().collect());
    assert_eq!(all, ALL_ROOTS.iter().copied().collect());
}

/// Mozilla ships roots with every trust bit turned off. They belong to the
/// collection but are not trust anchors, and shipping them as such would hand a
/// consumer more trust than Mozilla grants — so they appear in the table and in
/// no environment.
#[test]
fn untrusted_roots_are_in_the_table_but_in_no_environment() {
    let untrusted: Vec<_> = ROOTS.iter().filter(|r| !r.is_trusted()).collect();
    assert_eq!(untrusted.len(), EXPECTED_ROOTS - EXPECTED_ALL);
    for root in untrusted {
        assert!(!ALL_ROOTS.contains(&root.der), "{}", root.common_name);
        for entry in PROVIDER.entries() {
            assert!(
                !entry.roots.contains(&root.der),
                "{} appears in {}",
                root.common_name,
                entry.id
            );
        }
    }
}

/// The fingerprints are what a consumer looks up by, so they must be the hash
/// of the bytes beside them rather than the report's copy of it.
#[test]
fn fingerprints_match_the_embedded_bytes() {
    use sha2::{Digest, Sha256};

    for root in ROOTS.iter() {
        let hex: String = Sha256::digest(root.der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(
            hex, root.sha256_fingerprint,
            "fingerprint mismatch for {}",
            root.common_name
        );
        assert_eq!(
            find_by_sha256(&hex).map(|r| r.common_name),
            Some(root.common_name)
        );
    }
    assert!(find_by_sha256("not a fingerprint").is_none());
}

/// The out-of-band policy this crate exists to surface. These are properties of
/// the snapshot, not invariants — if a refresh drops the last distrust-after
/// date or the last applied constraint, relax the assertion rather than the
/// material.
#[test]
fn out_of_band_policy_is_carried_through() {
    let distrusted: Vec<_> = ROOTS
        .iter()
        .filter(|r| r.distrust_for_tls_after.is_some())
        .collect();
    assert!(
        !distrusted.is_empty(),
        "the snapshot had roots under a TLS distrust-after date; they must survive generation"
    );
    for root in &distrusted {
        // ISO 8601 calendar date, which is what makes these comparable against
        // an end entity's notBefore without parsing.
        let date = root.distrust_for_tls_after.unwrap();
        assert_eq!(date.len(), 10, "{} carries {date:?}", root.common_name);
        assert!(date.as_bytes()[4] == b'-' && date.as_bytes()[7] == b'-');
    }

    assert!(ROOTS
        .iter()
        .any(|r| r.mozilla_applied_constraints.is_some()));
}

#[test]
#[cfg(feature = "mozilla_tls")]
fn prepare_environment_accepts_mozilla_tls() {
    // Brings TaSource::len() into scope; kept local so the module compiles
    // with no features enabled.
    use certval::CertVector;

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();

    prepare_certval_environment(
        &providers(),
        &mut pe,
        &mut ta_store,
        certval_stores_mozilla::TLS,
    )
    .expect("the TLS store id must be recognized");
    assert_eq!(ta_store.len(), EXPECTED_TLS);
}

#[test]
#[cfg(feature = "mozilla_email")]
fn prepare_environment_accepts_mozilla_email() {
    // Brings TaSource::len() into scope; kept local so the module compiles
    // with no features enabled.
    use certval::CertVector;

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();

    prepare_certval_environment(
        &providers(),
        &mut pe,
        &mut ta_store,
        certval_stores_mozilla::EMAIL,
    )
    .expect("the S/MIME store id must be recognized");
    assert_eq!(ta_store.len(), EXPECTED_EMAIL);
}

#[test]
#[cfg(feature = "mozilla_all")]
fn prepare_environment_accepts_mozilla_all() {
    // Brings TaSource::len() into scope; kept local so the module compiles
    // with no features enabled.
    use certval::CertVector;

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();

    prepare_certval_environment(
        &providers(),
        &mut pe,
        &mut ta_store,
        certval_stores_mozilla::ALL,
    )
    .expect("the combined store id must be recognized");
    assert_eq!(ta_store.len(), EXPECTED_ALL);
}

#[test]
fn prepare_environment_rejects_unknown_environment() {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut ta_store = TaSource::new();

    let r = prepare_certval_environment(&providers(), &mut pe, &mut ta_store, "not_a_store_id");
    assert!(matches!(r, Err(Error::Unrecognized)));
}

/// The purpose-scoped environments are anchors-only: the CA store is one graph
/// over all 170 anchors, and attaching it to a 121- or 91-anchor entry would
/// leave paths that no anchor of that entry can terminate. `MOZILLA_ALL` is
/// where it hangs; see the `MozillaStores` docs.
#[test]
fn only_mozilla_all_carries_a_ca_store() {
    // The id constant exists only with the feature that carries the store, which is
    // the point of it being a constant. A build without that feature yields no such
    // entry either, so nothing is being skipped here.
    #[cfg(feature = "mozilla_all")]
    fn is_combined(id: &str) -> bool {
        id == certval_stores_mozilla::ALL
    }
    #[cfg(not(feature = "mozilla_all"))]
    fn is_combined(_id: &str) -> bool {
        false
    }

    for entry in &PROVIDER.entries() {
        assert!(!entry.roots.is_empty());
        let expected = is_combined(entry.id) && cfg!(feature = "mozilla_cas");
        assert_eq!(
            entry.cert_store_cbor.is_some(),
            expected,
            "{} carries a CA store: {}",
            entry.id,
            entry.cert_store_cbor.is_some()
        );
    }
}

/// The embedded CA store deserializes, initializes, and carries what the
/// generator put in it. A truncated or half-written `mozilla.cbor` fails here
/// rather than at a consumer's first path build.
#[test]
#[cfg(feature = "mozilla_cas")]
fn embedded_ca_store_deserializes_and_initializes() {
    use certval::{CertSource, CertVector};

    let cbor =
        certval_stores_mozilla::CA_STORE.expect("the mozilla_cas feature must embed a store");
    let mut cert_source = CertSource::new_from_cbor(cbor).expect("mozilla.cbor must deserialize");
    cert_source
        .initialize(&Default::default())
        .expect("mozilla.cbor must initialize");
    assert_eq!(cert_source.len(), EXPECTED_INTERMEDIATES);
}

/// Only the `.cbor` is compiled in; the `.der` files beside it are the
/// generator's inputs and affect nothing at run time, so they drift silently.
/// This compares the two sets in both directions — a certificate added to
/// `cas/mozilla/` without regenerating, or left behind after being dropped, is
/// caught here.
#[test]
#[cfg(feature = "mozilla_cas")]
fn generator_inputs_match_the_store() {
    use std::path::Path;

    let cbor =
        certval_stores_mozilla::CA_STORE.expect("the mozilla_cas feature must embed a store");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("cas/mozilla");
    let failures = conformance::check_generator_inputs(&dir, cbor);
    assert!(
        failures.is_empty(),
        "cas/mozilla has drifted from mozilla.cbor:\n - {}",
        failures.join("\n - ")
    );
}

/// The `roots/mozilla/*.der` files reach the crate through the `include_bytes!`
/// list in `src/generated.rs`, which the compiler only half-checks: remove a
/// file and the build breaks, add one and it ships looking like a root without
/// being in the table.
///
/// The comparison is against `ROOTS`, not against any environment's anchors,
/// because the directory holds the whole published population — including the
/// roots Mozilla trusts for nothing, which belong to the collection and
/// deliberately appear in no environment. Checking a subset here would report
/// every email-only and untrusted root as drift.
#[test]
fn root_inputs_match_the_embedded_population() {
    use std::path::Path;

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("roots/mozilla");
    let ders: Vec<&[u8]> = ROOTS.iter().map(|r| r.der).collect();
    let failures = conformance::check_root_inputs(&dir, &ders);
    assert!(
        failures.is_empty(),
        "roots/mozilla has drifted from the embedded population:\n - {}",
        failures.join("\n - ")
    );
}

/// Path *validation*, not just assembly: every CA in the store is reachable
/// from an embedded anchor with signatures verified the whole way down. The
/// environment comes from here rather than the harness because the crypto a
/// store needs is the provider's business — this crate's dev-dependency on
/// certval enables `rsa` for that reason. Settings are time-independent, so
/// this asks whether the material is sound rather than whether it is current;
/// plenty of these intermediates have expired and are kept deliberately.
#[test]
#[cfg(feature = "mozilla_cas")]
fn paths_validate_under_the_embedded_anchors() {
    conformance::assert_paths_validate(
        certval_stores_mozilla::provider(),
        conformance::default_environment,
        &conformance::structural_validation_settings(),
    );
}

/// Not a property of the crate but of the collection, and worth pinning
/// because consumers rely on it: nothing constrains the name space these
/// anchors can certify except `mozilla_applied_constraints`, which no RFC 5280
/// implementation applies on its own. If a refresh ever makes this fail, that
/// is news — investigate rather than deleting the test.
#[test]
fn no_root_carries_a_name_constraints_extension() {
    use certval::{parse_cert, ExtensionProcessing, PDVExtension};
    use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS};

    let mut constrained = vec![];
    let mut without_basic_constraints = vec![];
    for root in ROOTS.iter() {
        let mut cert = parse_cert(root.der, root.common_name).expect("every root must parse");
        // get_extension reads a cache parse_extensions fills, so the parse has
        // to happen first; an unparsed certificate reads as having no
        // extensions at all.
        cert.parse_extensions(&[ID_CE_NAME_CONSTRAINTS, ID_CE_BASIC_CONSTRAINTS]);
        if let Ok(Some(PDVExtension::NameConstraints(_))) =
            cert.get_extension(&ID_CE_NAME_CONSTRAINTS)
        {
            constrained.push(root.common_name);
        }
        // Positive control. A zero result is only meaningful if this machinery
        // finds an extension that *is* there — every one of these is a CA
        // certificate, so basicConstraints is present in all of them.
        if !matches!(
            cert.get_extension(&ID_CE_BASIC_CONSTRAINTS),
            Ok(Some(PDVExtension::BasicConstraints(_)))
        ) {
            without_basic_constraints.push(root.common_name);
        }
    }
    assert!(
        without_basic_constraints.is_empty(),
        "extension lookup is not finding extensions that are present: {without_basic_constraints:?}"
    );
    assert!(
        constrained.is_empty(),
        "roots now carry nameConstraints: {constrained:?}"
    );
}
