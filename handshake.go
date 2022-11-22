package nikea

import (
	"bytes"
	"crypto/ed25519"

	"git.oxc.ch/keron/nikea-go/kx"
)

type Config struct {
	Cipher CipherAlgo
	Hash   HashAlgo
}

var DefaultConfig = Config{
	XChaCha20Poly1305{},
	HashSHA512,
}

type Keys struct {
	// The local party's static key pair
	S KeyPair
	// The local party's ephemeral key pair
	E KeyPair
	// The remote party's static public key
	RS []byte
	// The remote party's ephemeral public key
	RE []byte
	// Signed keys of remote party
	RemoteIdentity Identity
}

// Identity provides key authentication
type Identity struct {
	Pubk []byte
	// static public key signature
	Ssig []byte
	// ephemeral public key signature
	Esig []byte
}

type Handshake struct {
	config Config
	keys   Keys
}

type SessionKeys struct {
	RX CipherState
	TX CipherState
}

func (hs Handshake) Initiate() (SessionKeys, error) {
	if err := hs.verifyRemoteSignatures(); err != nil {
		return SessionKeys{}, err
	}

	dhes, err := kx.ClientSessionKeys(hs.keys.E.PublicKey, hs.keys.E.SecretKey, hs.keys.RS)
	if err != nil {
		return SessionKeys{}, err
	}
	dhss, err := kx.ClientSessionKeys(hs.keys.S.PublicKey, hs.keys.S.SecretKey, hs.keys.RS)
	if err != nil {
		return SessionKeys{}, err
	}
	dhee, err := kx.ClientSessionKeys(hs.keys.E.PublicKey, hs.keys.E.SecretKey, hs.keys.RE)
	if err != nil {
		return SessionKeys{}, err
	}
	dhse, err := kx.ClientSessionKeys(hs.keys.S.PublicKey, hs.keys.S.SecretKey, hs.keys.RE)
	if err != nil {
		return SessionKeys{}, err
	}

	decH, encH, err := hs.buildSharedSecret(dhes, dhss, dhee, dhse)
	if err != nil {
		return SessionKeys{}, err
	}

	return SessionKeys{newCipherState(hs.config, ModeRX, decH), newCipherState(hs.config, ModeTX, encH)}, nil
}

func (hs Handshake) Respond() (SessionKeys, error) {
	if err := hs.verifyRemoteSignatures(); err != nil {
		return SessionKeys{}, err
	}

	dhes, err := kx.ServerSessionKeys(hs.keys.S.PublicKey, hs.keys.S.SecretKey, hs.keys.RE)
	if err != nil {
		return SessionKeys{}, err
	}
	dhss, err := kx.ServerSessionKeys(hs.keys.S.PublicKey, hs.keys.S.SecretKey, hs.keys.RS)
	if err != nil {
		return SessionKeys{}, err
	}
	dhee, err := kx.ServerSessionKeys(hs.keys.E.PublicKey, hs.keys.E.SecretKey, hs.keys.RE)
	if err != nil {
		return SessionKeys{}, err
	}
	dhse, err := kx.ServerSessionKeys(hs.keys.E.PublicKey, hs.keys.E.SecretKey, hs.keys.RS)
	if err != nil {
		return SessionKeys{}, err
	}

	decH, encH, err := hs.buildSharedSecret(dhes, dhss, dhee, dhse)
	if err != nil {
		return SessionKeys{}, err
	}

	return SessionKeys{newCipherState(hs.config, ModeRX, decH), newCipherState(hs.config, ModeTX, encH)}, nil
}

func (hs Handshake) verifyRemoteSignatures() error {
	if !ed25519.Verify(hs.keys.RemoteIdentity.Pubk, hs.keys.RS, hs.keys.RemoteIdentity.Ssig) {
		return &InvalidRemoteSignatureError{'s'}
	}
	if !ed25519.Verify(hs.keys.RemoteIdentity.Pubk, hs.keys.RE, hs.keys.RemoteIdentity.Esig) {
		return &InvalidRemoteSignatureError{'e'}
	}
	return nil
}

func New(config Config, keys Keys) Handshake {
	return Handshake{config, keys}
}

func (hs Handshake) buildSharedSecret(dhes kx.SessionKeys, dhss kx.SessionKeys, dhee kx.SessionKeys, dhse kx.SessionKeys) ([]byte, []byte, error) {
	var decHashBuf, encHashBuf bytes.Buffer

	// err is always nil
	_, _ = decHashBuf.WriteString(SharedSecret)
	_, _ = decHashBuf.Write(dhes.RX[:])
	_, _ = decHashBuf.Write(dhss.RX[:])
	_, _ = decHashBuf.Write(dhee.RX[:])
	_, _ = decHashBuf.Write(dhse.RX[:])

	hasher := hs.config.Hash.fn()
	if _, err := hasher.Write(decHashBuf.Bytes()); err != nil {
		return nil, nil, err
	}
	decHash := hasher.Sum(nil)

	_, _ = encHashBuf.WriteString(SharedSecret)
	_, _ = encHashBuf.Write(dhes.TX[:])
	_, _ = encHashBuf.Write(dhss.TX[:])
	_, _ = encHashBuf.Write(dhee.TX[:])
	_, _ = encHashBuf.Write(dhse.TX[:])

	hasher.Reset()
	if _, err := hasher.Write(encHashBuf.Bytes()); err != nil {
		return nil, nil, err
	}
	encHash := hasher.Sum(nil)

	return decHash, encHash, nil
}
