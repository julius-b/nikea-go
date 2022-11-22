# Nikea: Non-Interactive Key Agreement
Nikea provides end-to-end encrypted communication with offline handshake establishment.

To learn more about this library, __check out the Kotlin implementation__. This page only documents extra features.

## LibSodium KeyExchange
Package [kx](kx/) implements LibSodium's [Key exchange](https://doc.libsodium.org/key_exchange/)
- using Golang's implementation of [curve25519](https://pkg.go.dev/golang.org/x/crypto/curve25519) & [blake2b](https://pkg.go.dev/golang.org/x/crypto/blake2b)
- the alternative would be C-bindings, which require CGO

## Usage via Github
`go.mod`:
```
require (
  git.oxc.ch/keron/nikea-go v0.1.0
)

replace git.oxc.ch/keron/nikea-go => github.com/julius-b/nikea-go v0.1.0
```
