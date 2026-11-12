# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.
See the README's "Versioning" section for what each level means for the trust material.

## [1.0.0-rc.3] - 2026-11-12

### Changed
- The trust material is CCADB's as of 2026-11-09, from 2026-11-02.
- Buypass Class 2 Root CA and Buypass Class 3 Root CA are no longer included: 167 roots, from 169.
- Trust bits changed, so the TLS store holds 112 roots, from 118, and the email store 83, from 88:
  - Websites removed from DigiCert Trusted Root G4, QuoVadis Root CA 1 G3, QuoVadis Root CA 3 G3
    and Certigna Root CA.
  - Email removed from DigiCert Global Root G2, DigiCert Global Root G3, IdenTrust Commercial Root
    CA 1, UCA Global G2 Root and emSign Root CA - G1.
- emSign Root CA - G1 is distrusted for TLS certificates issued after 2026-11-16, and Autoridad de
  Certificacion Firmaprofesional CIF A62634068 for those issued after 2026-08-06.
- The intermediate-CA store (`mozilla_cas`) carries 2505 certificates, from 2538. It adds two
  Telekom Security SMIME roots, TWCA SMIME Root CA G1 and a TWCA InfoSec User CA, and drops 37,
  among them the BJCA, Xinnet and Cybertrust Japan SureServer SSL CAs, the Buypass CAs, several
  TWCA CAs, and WoSign OV SSL CA, which expired on 2026-11-09.

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
