package nikea

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherAlgo interface {
	Encrypt(plaintext []byte, ad []byte, nonce []byte, key []byte) (ciphertext []byte, err error)
	Decrypt(ciphertextAndTag []byte, ad []byte, nonce []byte, key []byte) (plaintext []byte, err error)
}

// NOTE: this is only efficient when the key changes with every message
type XChaCha20Poly1305 struct{}

// key sizes checked by stdlib
func (c XChaCha20Poly1305) Encrypt(plaintext []byte, ad []byte, nonce []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Seal with `nonce` as first parameter: `nonce [aead.NonceSize()] || ciphertext || tag [aead.Overhead()]`
	// everything after aead.NonceSize() is the same
	//ciphertextSealed := aead.Seal(nonce, nonce, plaintext, ad)
	//ciphertextAndTag := ciphertextSealed[aead.NonceSize():]
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func (c XChaCha20Poly1305) Decrypt(ciphertextAndTag []byte, ad []byte, nonce []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// nonce is not prepended
	//nonce, ciphertextAndTag := ciphertext[:chacha20poly1305.NonceSize], ciphertext[chacha20poly1305.NonceSize:]
	return aead.Open(nil, nonce, ciphertextAndTag, ad)
}

// `func([]byte) [32]byte` with `sha256.Sum256` may be more conventient but isn't as extensible
type HashAlgo struct {
	fn   func() hash.Hash
	name string
}

var HashSHA256 HashAlgo = HashAlgo{sha256.New, "SHA256"}
var HashSHA512 HashAlgo = HashAlgo{sha512.New, "SHA512"}
