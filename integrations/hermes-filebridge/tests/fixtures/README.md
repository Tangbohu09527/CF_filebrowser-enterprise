These public, non-secret `cert.pem` and `key.pem` files are ONLY for the isolated
127.0.0.1 HTTPS test server. Never deploy them or install this CA in a trust store.
The client tests pin this CA in their own temporary binding.

`sample.pdf` is a generated one-page empty PDF with an explicit xref table.
`sample.jpg` is a generated 2×2 JPEG. Neither contains business or personal data.

Generated with Go 1.25.0's `src/crypto/tls/generate_cert.go`, `-ca
-ecdsa-curve P256 -host 127.0.0.1 -start-date "Jan 1 00:00:00 2020"
-duration 262800h`. This intentionally does not cover the hostname `localhost`.
