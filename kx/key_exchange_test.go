package kx

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.org/x/crypto/curve25519"
)

// compatibility test with LibSodium bindings & documented keys
func TestKeyExchangeConst(t *testing.T) {
	x25519Seed, err := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	assert.NoError(t, err)

	x25519Pubk, err := curve25519.X25519(x25519Seed, curve25519.Basepoint)
	assert.NoError(t, err)

	otherX25519Seed, err := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	assert.NoError(t, err)

	otherX25519Pubk, err := curve25519.X25519(otherX25519Seed, curve25519.Basepoint)
	assert.NoError(t, err)

	kexSK, err := ClientSessionKeys(x25519Pubk, x25519Seed, otherX25519Pubk)
	assert.NoError(t, err)
	otherKexSK, err := ServerSessionKeys(otherX25519Pubk, otherX25519Seed, x25519Pubk)
	assert.NoError(t, err)

	assert.Equal(t, kexSK.RX, otherKexSK.TX)
	assert.Equal(t, kexSK.TX, otherKexSK.RX)
	assert.NotEqual(t, kexSK.RX, otherKexSK.RX)
	assert.NotEqual(t, kexSK.TX, otherKexSK.TX)

	assert.Equal(t, "1ad7d1f6d5270fbb18123f3bc904c7f97283e7d47bbe85606ee5ded0af2608c5", fmt.Sprintf("%x", kexSK.RX))
	assert.Equal(t, "9aede84a8737da34d203e31b6daed56b52c5316a7c9d028621b2717fdaa2d314", fmt.Sprintf("%x", kexSK.TX))
}
