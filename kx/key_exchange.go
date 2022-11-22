package kx

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

// implements LibSodium KeyExchange in golang
// Blake2b is hardcoded in Libsodium (v1.0.18-stable)
// doc: https://doc.libsodium.org/key_exchange/

// crypto_kx_PUBLICKEYBYTES
const PublicKeyBytes = 32

// crypto_kx_SECRETKEYBYTES
const SecretKeyBytes = 32

// crypto_kx_SESSIONKEYBYTES
const SessionKeyBytes = 32

type SessionKeys struct {
	RX [SessionKeyBytes]byte
	TX [SessionKeyBytes]byte
}

func Keypair() (pk []byte, sk []byte, err error) {
	sk = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sk); err != nil {
		return nil, nil, err
	}
	pk, err = curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return
}

// NOTE: expecting `clientPK [PublicKeyBytes]byte` makes it much harder to use this library: `*(*[32]byte)(x25519Pubk)`
// the stdlib does these checks already
func ClientSessionKeys(clientPK []byte, clientSK []byte, serverPK []byte) (SessionKeys, error) {
	n, err := curve25519.X25519(clientSK[:], serverPK[:])
	if err != nil {
		return SessionKeys{}, err
	}

	// `rx || tx = BLAKE2B-512(p.n || client_pk || server_pk)`
	rootKey := append(append(n, clientPK[:]...), serverPK[:]...)
	hash := blake2b.Sum512(rootKey)

	//copy(rx[:], hash[:SessionKeyBytes])
	// `*(*[32]byte)()` syntax more efficient than a byte-by-byte copy
	return SessionKeys{
		*(*[32]byte)(hash[:SessionKeyBytes]),
		*(*[32]byte)(hash[SessionKeyBytes:]),
	}, nil
}

func ServerSessionKeys(serverPK []byte, serverSK []byte, clientPK []byte) (SessionKeys, error) {
	// swapped order -> same n
	n, err := curve25519.X25519(serverSK[:], clientPK[:])
	if err != nil {
		return SessionKeys{}, err
	}

	// same order -> same rootKey
	rootKey := append(append(n, clientPK[:]...), serverPK[:]...)
	hash := blake2b.Sum512(rootKey)

	// swapped order -> matching rx -> tx
	// rx for client is first part -> tx for server is first part
	return SessionKeys{
		*(*[32]byte)(hash[SessionKeyBytes:]),
		*(*[32]byte)(hash[:SessionKeyBytes]),
	}, nil
}
