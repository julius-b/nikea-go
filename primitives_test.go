package nikea

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/sign"
)

func TestEd25519Const(t *testing.T) {
	ed25519Seed, err := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	assert.NoError(t, err)

	ed25519Key := ed25519.NewKeyFromSeed(ed25519Seed)
	assert.Equal(t, "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737", fmt.Sprintf("%x", ed25519Key.Public()))

	ed25519PubkBytes := []byte(ed25519Key.Public().(ed25519.PublicKey))
	pubkSig := ed25519.Sign(ed25519Key, ed25519PubkBytes)
	t.Logf("goed sig: %x", pubkSig)
	assert.Equal(t, "f25bc1115ba369af4fbab86a4274bbecddd536b53b5ec3ac8e3658aacb5319b879674e74738803d1afac224176ae11a011a17cb07e0c65e99432c2f0b1edc307", fmt.Sprintf("%x", pubkSig))

	assert.True(t, ed25519.Verify(ed25519PubkBytes, ed25519PubkBytes, pubkSig))

	// "nacl" same output
	out := make([]byte, 0, sign.Overhead+len(ed25519PubkBytes))
	pubkSig2 := sign.Sign(out, ed25519PubkBytes, (*[64]byte)(ed25519Key))
	t.Logf("nacl sig: %x", pubkSig2[:sign.Overhead])
}

func TestX25519Const(t *testing.T) {
	// source: https://github.com/flynn/noise/blob/master/cipher_suite.go#L107
	x25519Seed, err := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	assert.NoError(t, err)

	x25519Pubk, err := curve25519.X25519(x25519Seed, curve25519.Basepoint)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%x", x25519Pubk), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

	otherX25519Seed, err := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	assert.NoError(t, err)

	otherX25519Pubk, err := curve25519.X25519(otherX25519Seed, curve25519.Basepoint)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%x", otherX25519Pubk), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	sharedSecretA, err := curve25519.X25519(x25519Seed, otherX25519Pubk)
	assert.NoError(t, err)
	sharedSecretB, err := curve25519.X25519(otherX25519Seed, x25519Pubk)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%x", sharedSecretA), fmt.Sprintf("%x", sharedSecretB))
	assert.Equal(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", fmt.Sprintf("%x", sharedSecretA))
}

func TestXChaChaPoly1305Const(t *testing.T) {
	var aead XChaCha20Poly1305

	key1, err := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	assert.NoError(t, err)
	key2, err := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	assert.NoError(t, err)

	expectedCiphertext1, err := hex.DecodeString("907917d21ece996ac8ecad83c352805bdca225ae7dfd62412d63c7")
	assert.NoError(t, err)
	expectedCiphertext2, err := hex.DecodeString("4f18cd2b55da419599694380882c07a7637b61b610c9cdef867ea0")
	assert.NoError(t, err)

	nonce := make([]byte, 16, 24)
	nonce = binary.BigEndian.AppendUint64(nonce, 1)
	t.Logf("nonce: %+v", nonce)

	ciphertext1, err := aead.Encrypt([]byte("Hello World"), nil, nonce, key1)
	assert.NoError(t, err)
	assert.Equal(t, expectedCiphertext1, ciphertext1)

	ciphertext2, err := aead.Encrypt([]byte("Hello World"), nil, nonce, key2)
	assert.NoError(t, err)
	assert.Equal(t, expectedCiphertext2, ciphertext2)
}
