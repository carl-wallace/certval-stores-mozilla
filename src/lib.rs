// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![doc = include_str!("../README.md")]

mod generated;

pub use generated::{ALL_ROOTS, CCADB_REPORT_URL, EMAIL_ROOTS, ROOTS, SNAPSHOT_DATE, TLS_ROOTS};

use certval_stores_core::{StoreEntry, TrustStoreProvider};

/// One root from Mozilla's included-CA report, with the metadata CCADB
/// publishes beside it.
///
/// The metadata is the reason this crate carries a table rather than a bare
/// list of DER buffers: two of the fields — [`distrust_for_tls_after`] and
/// [`mozilla_applied_constraints`] — are *restrictions Mozilla applies to a root
/// that are not expressed in the certificate*. Nothing in RFC 5280 processing
/// can see them, so a relying party that wants Mozilla's actual trust decision
/// rather than an approximation of it has to apply them itself, after path
/// validation. See [`find_by_sha256`].
///
/// Dates are ISO 8601 calendar dates (`YYYY-MM-DD`) in UTC, converted from the
/// `YYYY.MM.DD` form CCADB publishes. They are strings rather than a date type
/// so this crate stays dependency-free apart from the provider trait.
///
/// [`distrust_for_tls_after`]: MozillaRoot::distrust_for_tls_after
/// [`mozilla_applied_constraints`]: MozillaRoot::mozilla_applied_constraints
pub struct MozillaRoot {
    /// The certificate, DER-encoded.
    pub der: &'static [u8],
    /// CCADB's "Common Name or Certificate Name" for this root.
    pub common_name: &'static str,
    /// The CA organization that operates it.
    pub owner: &'static str,
    /// Uppercase hex SHA-256 of [`der`](MozillaRoot::der).
    pub sha256_fingerprint: &'static str,
    /// Whether the Websites (TLS server authentication) trust bit is set.
    pub websites: bool,
    /// Whether the Email (S/MIME) trust bit is set.
    pub email: bool,
    /// notBefore of the certificate.
    pub not_before: &'static str,
    /// notAfter of the certificate.
    pub not_after: &'static str,
    /// CCADB's description of the public key, e.g. `"RSA 4096 bits"`.
    pub public_key_algorithm: &'static str,
    /// Mozilla distrusts TLS certificates issued under this root with a
    /// notBefore after this date, while continuing to trust earlier ones. It is
    /// how a CA is wound down without breaking certificates already issued —
    /// and it is invisible to path validation, so a TLS consumer must apply it
    /// to the end-entity's notBefore itself.
    pub distrust_for_tls_after: Option<&'static str>,
    /// The S/MIME counterpart of [`distrust_for_tls_after`](MozillaRoot::distrust_for_tls_after).
    pub distrust_for_smime_after: Option<&'static str>,
    /// Constraints Mozilla applies to this root outside the certificate, as
    /// free text (CCADB does not structure this field). Values seen in practice
    /// are a domain restriction such as `"*.tr"` and the explicit
    /// `"No name constraints are to be applied"`.
    ///
    /// Where a value names domains, it is the moral equivalent of a
    /// `nameConstraints` extension the root does not carry: **no** root in this
    /// collection carries that extension at all, so this field is the only
    /// name constraint on any of these anchors.
    pub mozilla_applied_constraints: Option<&'static str>,
}

impl MozillaRoot {
    /// Whether Mozilla trusts this root for anything at all.
    ///
    /// The report includes roots with every trust bit turned off. They are part
    /// of the collection — NSS still ships them, and they still appear in
    /// [`ROOTS`] — but they are not trust anchors, so they are absent from
    /// [`TLS_ROOTS`], [`EMAIL_ROOTS`], and [`ALL_ROOTS`], and from every
    /// environment this crate's provider serves.
    pub fn is_trusted(&self) -> bool {
        self.websites || self.email
    }
}

/// The root in [`ROOTS`] with the given uppercase-hex SHA-256 fingerprint, if
/// any.
///
/// This is the bridge from a validated path back to Mozilla's out-of-band
/// policy: hash the trust anchor certval anchored on, look it up here, and
/// apply [`distrust_for_tls_after`](MozillaRoot::distrust_for_tls_after) and
/// [`mozilla_applied_constraints`](MozillaRoot::mozilla_applied_constraints) to
/// the result. A path that validates under a root carrying a distrust-after
/// date is *not* a path Mozilla would accept if the end entity's notBefore
/// falls after it.
///
/// A linear scan over 172 entries; the table is sorted by name, not by
/// fingerprint, so ordering it for a binary search would fix the display order
/// to the lookup order for no measurable gain.
pub fn find_by_sha256(fingerprint: &str) -> Option<&'static MozillaRoot> {
    ROOTS
        .iter()
        .find(|r| r.sha256_fingerprint.eq_ignore_ascii_case(fingerprint))
}

/// The serialized certval `CertSource` of intermediate CAs — buffers plus the
/// precomputed partial-path graph — or `None` when the `mozilla_cas` feature is
/// off.
///
/// Every intermediate CCADB discloses under the Mozilla program that chains to
/// an embedded root: 2,560 certificates, 6.6 MB. It is what lets a path build
/// offline, with no AIA fetch and no chain from a peer — which is the normal
/// case for pittv3-style validation of a certificate file, for a TLS server
/// that sends an incomplete chain, and for an S/MIME message or a client-auth
/// handshake where the signer certificate arrives with no issuers at all.
///
/// Exposed so a consumer can build its own `CertSource::new_from_cbor` rather
/// than going through [`prepare_certval_environment`].
///
/// [`prepare_certval_environment`]: certval_stores_core::prepare_certval_environment
#[cfg(feature = "mozilla_cas")]
pub const CA_STORE: Option<&'static [u8]> = Some(include_bytes!("../cas/mozilla/mozilla.cbor"));

/// No CA store is embedded; enable the `mozilla_cas` feature to get one.
#[cfg(not(feature = "mozilla_cas"))]
pub const CA_STORE: Option<&'static [u8]> = None;

/// Trust-store provider for the Mozilla root program.
///
/// Every entry reports [`SNAPSHOT_DATE`] as its collection date and no publication
/// date. The report is a live query rather than a dated release — CCADB answers with
/// whatever it holds at the moment it is asked — so the day `tools/refresh.py` ran is
/// the only date there is, and claiming it as a publication date would dress a fetch
/// up as a publisher's statement. The intermediates come from the same run, so the
/// date covers `CA_STORE` as well as the roots.
///
/// `MOZILLA_TLS` and `MOZILLA_EMAIL` are anchors-only. `MOZILLA_ALL` carries
/// [`CA_STORE`] when the `mozilla_cas` feature is on.
///
/// **Why the CA store hangs off `MOZILLA_ALL` alone.** The store is one graph
/// over all 170 anchors, and 85% of it is common to the two purpose-scoped
/// environments — shipping a pruned copy for each would triple 6.6 MB to buy
/// almost nothing. It cannot simply be shared: the conformance suite requires
/// every serialized path to start at a CA the *entry's own* anchors issued, and
/// 356 of these chain only to email-only roots, so attaching this graph to
/// `MOZILLA_TLS` would report those as unanchored.
///
/// The consequence is a division of labour that this crate already applies to
/// Mozilla's other out-of-band policy: **build paths widely, then decide trust
/// from the metadata**. Anchor on `MOZILLA_ALL`, and once a path validates, look
/// its anchor up with [`find_by_sha256`] and check
/// [`websites`](MozillaRoot::websites) or [`email`](MozillaRoot::email) for the
/// purpose you care about — the same step already needed for
/// [`distrust_for_tls_after`](MozillaRoot::distrust_for_tls_after). A consumer
/// that would rather have the anchor set enforce the purpose takes
/// `MOZILLA_TLS` or `MOZILLA_EMAIL` and supplies intermediates itself.
pub struct MozillaStores;

/// Store id for the Mozilla TLS-only root set, to pass to `prepare_certval_environment` or
/// `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "mozilla_tls")]
pub const TLS: &str = "webpki_tls";

/// Store id for the Mozilla S/MIME-only root set, to pass to `prepare_certval_environment` or
/// `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "mozilla_email")]
pub const EMAIL: &str = "webpki_email";

/// Store id for the combined Mozilla root set with CCADB intermediates, to pass to `prepare_certval_environment` or
/// `serialize_environment` rather than spelling it out: the parameter is a
/// `&str`, so a stale literal compiles and fails at run time.
#[cfg(feature = "mozilla_all")]
pub const ALL: &str = "webpki";

impl TrustStoreProvider for MozillaStores {
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn entries(&self) -> Vec<StoreEntry> {
        let mut entries = Vec::new();
        #[cfg(feature = "mozilla_tls")]
        entries.push(StoreEntry {
            id: TLS,
            label: "Web PKI (Mozilla roots, TLS only)",
            roots: TLS_ROOTS,
            cert_store_cbor: None,
            published: None,
            collected: Some(SNAPSHOT_DATE),
        });
        #[cfg(feature = "mozilla_email")]
        entries.push(StoreEntry {
            id: EMAIL,
            label: "Web PKI (Mozilla roots, S/MIME only)",
            roots: EMAIL_ROOTS,
            cert_store_cbor: None,
            published: None,
            collected: Some(SNAPSHOT_DATE),
        });
        #[cfg(feature = "mozilla_all")]
        entries.push(StoreEntry {
            id: ALL,
            label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)",
            roots: ALL_ROOTS,
            cert_store_cbor: CA_STORE,
            published: None,
            collected: Some(SNAPSHOT_DATE),
        });
        entries
    }
}

/// The provider instance.
pub static PROVIDER: MozillaStores = MozillaStores;

/// Convenience accessor returning the provider as a trait object, for adding to
/// a provider list passed to `certval_stores_core`.
pub fn provider() -> &'static dyn TrustStoreProvider {
    &PROVIDER
}
