# Changes Logs

## v1.0.0

- feat(ec): added EC keys and certs supports.

## v0.3.3

- config(deps): updated development deps.
- config(deps): replaced exception with "@litert/exception".

## v0.3.2

- Fixed the X509 extension decoding.

## v0.3.1

- Fixed the dependencies.

## v0.3.0

- Added: method `validate` for class `CertificateManager`.
- Added: RSA key decoders.
- Now the x509 decoder could decode the content of RSA public key.

## v0.2.0

- Added: method `findExpiringCertificates` for class `CertificateManager`.
- Added: method `clear` for class `CertificateManager`.
- Fixed: method `use` of class `CertificateManager` can not update certificate.
