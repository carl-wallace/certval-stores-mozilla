# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.
See the README's "Versioning" section for what each level means for the trust material.

## [1.0.0-rc.2] - 2026-11-06

### Changed
- The trust material is CCADB's as of 2026-11-02, from 2026-10-25. The 169 roots are unchanged.
- The intermediate-CA store (`mozilla_cas`) adds TWCA CYBER Root CA, two TWCA CYBER Root CA G3
  certificates, and Verokey Secure ID SMIME ECC and Verokey Secure ID SMIME RSA, and drops QuoVadis
  Global SSL ICA G3, which expired on 2026-11-02.
- The minimum supported Rust version is 1.89.

## [1.0.0-rc.1] - 2026-10-29

Initial release, with a store behind each of the `mozilla_tls`, `mozilla_email` and `mozilla_all`
features, and the intermediate-CA store behind `mozilla_cas`.
