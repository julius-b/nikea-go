package nikea

import (
	"encoding/binary"
	"log"
)

type CipherStateMode byte

const (
	ModeRX   CipherStateMode = 'r'
	ModeTX   CipherStateMode = 't'
	ModeRXTX CipherStateMode = 'x'
)

var AD = []byte{}

type CipherState struct {
	config Config
	mode   CipherStateMode
	// sha512, 32 in Noise
	k [64]byte
	n uint64
}

func newCipherState(config Config, mode CipherStateMode, k []byte) CipherState {
	return CipherState{
		config: config,
		mode:   mode,
		k:      *(*[64]byte)(k),
	}
}

func (cs *CipherState) Encrypt(plaintext []byte) ([]byte, error) {
	if cs.mode == ModeRX {
		return nil, &IllegalCryptoOperation{cs.mode}
	}
	nonce := cs.ratchet()
	return cs.config.Cipher.Encrypt(plaintext, AD, nonce, cs.k[:32])
}

func (cs *CipherState) Decrypt(ciphertextAndTag []byte) ([]byte, error) {
	if cs.mode == ModeTX {
		return nil, &IllegalCryptoOperation{cs.mode}
	}
	nonce := cs.ratchet()
	return cs.config.Cipher.Decrypt(ciphertextAndTag, AD, nonce, cs.k[:32])
}

func (cs *CipherState) ratchet() []byte {
	cs.n++
	nonce := make([]byte, 16, 24)
	nonce = binary.BigEndian.AppendUint64(nonce, 1)
	hasher := cs.config.Hash.fn()
	if _, err := hasher.Write(cs.k[:]); err != nil {
		panic(err)
	}
	cs.k = *(*[64]byte)(hasher.Sum(nil))
	log.Printf("CipherState > ratchet - n: %d / %v (%d), key: %d-%d (%d)", cs.n, nonce, len(nonce), cs.k[0], cs.k[len(cs.k)-1], len(cs.k))
	return nonce
}
