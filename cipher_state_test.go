package nikea

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func genSessionKeys(sharedSecretAliceEnc, sharedSecretBobEnc []byte) (SessionKeys, SessionKeys, error) {
	if len(sharedSecretAliceEnc) == 0 {
		sharedSecretAliceEnc = make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, sharedSecretAliceEnc); err != nil {
			return SessionKeys{}, SessionKeys{}, err
		}
	}
	if len(sharedSecretBobEnc) == 0 {
		sharedSecretBobEnc = make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, sharedSecretBobEnc); err != nil {
			return SessionKeys{}, SessionKeys{}, err
		}
	}

	aliceSK := SessionKeys{
		newCipherState(DefaultConfig, ModeRX, sharedSecretBobEnc),
		newCipherState(DefaultConfig, ModeTX, sharedSecretAliceEnc),
	}
	bobSK := SessionKeys{
		newCipherState(DefaultConfig, ModeRX, sharedSecretAliceEnc),
		newCipherState(DefaultConfig, ModeTX, sharedSecretBobEnc),
	}
	return aliceSK, bobSK, nil
}

func TestConst(t *testing.T) {
	sharedSecretAliceEnc, _ := hex.DecodeString("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111")
	sharedSecretBobEnc, _ := hex.DecodeString("22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222")

	alice, bob, err := genSessionKeys(sharedSecretAliceEnc, sharedSecretBobEnc)
	assert.NoError(t, err)

	bobEnc1, err := bob.TX.Encrypt([]byte("Hello World"))
	assert.NoError(t, err)
	assert.Equal(t, "991dca71f67f5339a0107ca9863c828ddeaf1adf1a3ecfe69626c8", hex.EncodeToString(bobEnc1))

	aliceEnc1, err := alice.TX.Encrypt([]byte("Hello World"))
	assert.NoError(t, err)
	assert.Equal(t, "7cd82b70e23672efbc63b0217a37d523180f901aa0ae3cda33e924", hex.EncodeToString(aliceEnc1))
}

func TestRatchet(t *testing.T) {
	alice, bob, err := genSessionKeys(nil, nil)
	assert.NoError(t, err)

	bobEnc1, err := bob.TX.Encrypt([]byte("bobEnc1-msg"))
	assert.NoError(t, err)
	aliceDec1, err := alice.RX.Decrypt(bobEnc1)
	assert.NoError(t, err)
	assert.Equal(t, "bobEnc1-msg", string(aliceDec1))

	assert.Equal(t, bob.TX.n, alice.RX.n)
	assert.Equal(t, bob.TX.k, alice.RX.k)
	assert.NotEqual(t, bob.TX.n, alice.TX.n)
	assert.NotEqual(t, bob.TX.k, alice.TX.k)

	bobEnc2, err := bob.TX.Encrypt([]byte("bobEnc2-msg"))
	assert.NoError(t, err)
	aliceDec2, err := alice.RX.Decrypt(bobEnc2)
	assert.NoError(t, err)
	assert.Equal(t, "bobEnc2-msg", string(aliceDec2))

	assert.Equal(t, bob.TX.n, alice.RX.n)
	assert.Equal(t, bob.TX.k, alice.RX.k)

	bobEnc3, err := bob.TX.Encrypt([]byte("bobEnc3-msg"))
	assert.NoError(t, err)

	aliceEnc1, err := alice.TX.Encrypt([]byte("aliceEnc1-msg"))
	assert.NoError(t, err)

	aliceDec3, err := alice.RX.Decrypt(bobEnc3)
	assert.NoError(t, err)
	assert.Equal(t, "bobEnc3-msg", string(aliceDec3))

	bobDec1, err := bob.RX.Decrypt(aliceEnc1)
	assert.NoError(t, err)
	assert.Equal(t, "aliceEnc1-msg", string(bobDec1))
}

func TestIllegalDecrypt(t *testing.T) {
	alice, _, err := genSessionKeys(nil, nil)
	assert.NoError(t, err)

	_, err = alice.RX.Encrypt([]byte("rx can't encrypt"))
	if assert.Error(t, err) {
		assert.Equal(t, &IllegalCryptoOperation{ModeRX}, err)
	}
	_, err = alice.TX.Decrypt([]byte("tx can't decrypt"))
	if assert.Error(t, err) {
		assert.Equal(t, &IllegalCryptoOperation{ModeTX}, err)
	}
}

func TestBadDecrypt(t *testing.T) {
	_, bob, err := genSessionKeys(nil, nil)
	assert.NoError(t, err)

	fakeCiphertext := make([]byte, 32+16)
	for k := range fakeCiphertext {
		fakeCiphertext[k] = 0x1
	}
	_, err = bob.RX.Decrypt(fakeCiphertext)
	if assert.Error(t, err) {
		// errOpen private in chacha20poly1305
		assert.Equal(t, errors.New("chacha20poly1305: message authentication failed"), err)
	}
}
