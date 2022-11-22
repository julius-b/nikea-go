package nikea

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"git.oxc.ch/keron/nikea-go/kx"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
)

func TestOpenHandshake(t *testing.T) {
	bobPubk, bobSeck, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	alicePubk, aliceSeck, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	bobStaticPubk, bobStaticSeck, err := kx.Keypair()
	assert.NoError(t, err)
	bobEphemeralPubk, bobEphemeralSeck, err := kx.Keypair()
	assert.NoError(t, err)
	aliceStaticPubk, aliceStaticSeck, err := kx.Keypair()
	assert.NoError(t, err)
	aliceEphemeralPubk, aliceEphemeralSeck, err := kx.Keypair()
	assert.NoError(t, err)

	aliceStaticSig := ed25519.Sign(aliceSeck, aliceStaticPubk)
	aliceEphemeralSig := ed25519.Sign(aliceSeck, aliceEphemeralPubk)

	bobKeys := Keys{
		S:  KeyPair{bobStaticSeck, bobStaticPubk},
		E:  KeyPair{bobEphemeralSeck, bobEphemeralPubk},
		RS: aliceStaticPubk,
		RE: aliceEphemeralPubk,
		RemoteIdentity: Identity{
			Pubk: alicePubk,
			Ssig: aliceStaticSig,
			Esig: aliceEphemeralSig,
		},
	}

	bobStaticSig := ed25519.Sign(bobSeck, bobStaticPubk)
	bobEphemeralSig := ed25519.Sign(bobSeck, bobEphemeralPubk)

	aliceKeys := Keys{
		S:  KeyPair{aliceStaticSeck, aliceStaticPubk},
		E:  KeyPair{aliceEphemeralSeck, aliceEphemeralPubk},
		RS: bobStaticPubk,
		RE: bobEphemeralPubk,
		RemoteIdentity: Identity{
			Pubk: bobPubk,
			Ssig: bobStaticSig,
			Esig: bobEphemeralSig,
		},
	}

	initHs := New(DefaultConfig, bobKeys)
	respHs := New(DefaultConfig, aliceKeys)

	initSK, err := initHs.Initiate()
	assert.NoError(t, err)

	respSK, err := respHs.Respond()
	assert.NoError(t, err)

	assert.Equal(t, initSK.TX.k, respSK.RX.k)
	assert.Equal(t, initSK.RX.k, respSK.TX.k)
}

func TestHandshakeConst(t *testing.T) {
	bobIdentSeed, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	bobIdentKey := ed25519.NewKeyFromSeed(bobIdentSeed)

	aliceIdentSeed, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	aliceIdentKey := ed25519.NewKeyFromSeed(aliceIdentSeed)

	bobStaticSeed, _ := hex.DecodeString("3333333333333333333333333333333333333333333333333333333333333333")
	bobStaticPubk, _ := curve25519.X25519(bobStaticSeed, curve25519.Basepoint)

	bobEphemeralSeed, _ := hex.DecodeString("4444444444444444444444444444444444444444444444444444444444444444")
	bobEphemeralPubk, _ := curve25519.X25519(bobEphemeralSeed, curve25519.Basepoint)

	aliceStaticSeed, _ := hex.DecodeString("5555555555555555555555555555555555555555555555555555555555555555")
	aliceStaticPubk, _ := curve25519.X25519(aliceStaticSeed, curve25519.Basepoint)

	aliceEphemeralSeed, _ := hex.DecodeString("6666666666666666666666666666666666666666666666666666666666666666")
	aliceEphemeralPubk, _ := curve25519.X25519(aliceEphemeralSeed, curve25519.Basepoint)

	aliceStaticSig := ed25519.Sign(aliceIdentKey, aliceStaticPubk)
	aliceEphemeralSig := ed25519.Sign(aliceIdentKey, aliceEphemeralPubk)

	bobKeys := Keys{
		S:  KeyPair{bobStaticSeed, bobStaticPubk},
		E:  KeyPair{bobEphemeralSeed, bobEphemeralPubk},
		RS: aliceStaticPubk,
		RE: aliceEphemeralPubk,
		RemoteIdentity: Identity{
			Pubk: []byte(aliceIdentKey.Public().(ed25519.PublicKey)),
			Ssig: aliceStaticSig,
			Esig: aliceEphemeralSig,
		},
	}

	bobStaticSig := ed25519.Sign(bobIdentKey, bobStaticPubk)
	bobEphemeralSig := ed25519.Sign(bobIdentKey, bobEphemeralPubk)

	aliceKeys := Keys{
		S:  KeyPair{aliceStaticSeed, aliceStaticPubk},
		E:  KeyPair{aliceEphemeralSeed, aliceEphemeralPubk},
		RS: bobStaticPubk,
		RE: bobEphemeralPubk,
		RemoteIdentity: Identity{
			Pubk: []byte(bobIdentKey.Public().(ed25519.PublicKey)),
			Ssig: bobStaticSig,
			Esig: bobEphemeralSig,
		},
	}

	initHs := New(DefaultConfig, bobKeys)
	respHs := New(DefaultConfig, aliceKeys)

	initSK, err := initHs.Initiate()
	assert.NoError(t, err)

	respSK, err := respHs.Respond()
	assert.NoError(t, err)

	assert.Equal(t, "c217eb5894bde10b0db38930b87567b51e61d80713826ce418b7a2cbbb0fdebf9093fa29dc745d2e226c631c46293564fa7173a9c418eb642f8a964709e476ac", fmt.Sprintf("%x", initSK.RX.k))
	assert.Equal(t, "15e0e8f39c09208d6a2fcb04402aa197f6398f942386ca88ecc121c60d0c455fed0c8787c0337141eeab83c362c765198efa73787357f39eee459327344213f6", fmt.Sprintf("%x", initSK.TX.k))
	assert.Equal(t, "15e0e8f39c09208d6a2fcb04402aa197f6398f942386ca88ecc121c60d0c455fed0c8787c0337141eeab83c362c765198efa73787357f39eee459327344213f6", fmt.Sprintf("%x", respSK.RX.k))
	assert.Equal(t, "c217eb5894bde10b0db38930b87567b51e61d80713826ce418b7a2cbbb0fdebf9093fa29dc745d2e226c631c46293564fa7173a9c418eb642f8a964709e476ac", fmt.Sprintf("%x", respSK.TX.k))
}

func TestInvalidRemoteSignature(t *testing.T) {
	correctPubk, correctSeck, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	_, badSeck, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	staticPubk, _, err := kx.Keypair()
	assert.NoError(t, err)
	ephemeralPubk, _, err := kx.Keypair()
	assert.NoError(t, err)

	hs := New(DefaultConfig, Keys{
		RS: staticPubk,
		RE: ephemeralPubk,
		RemoteIdentity: Identity{
			Pubk: correctPubk,
			Ssig: ed25519.Sign(correctSeck, staticPubk),
			Esig: ed25519.Sign(badSeck, ephemeralPubk),
		},
	})
	err = hs.verifyRemoteSignatures()
	if assert.Error(t, err) {
		assert.Equal(t, &InvalidRemoteSignatureError{'e'}, err)
	}

	hs = New(DefaultConfig, Keys{
		RS: staticPubk,
		RE: ephemeralPubk,
		RemoteIdentity: Identity{
			Pubk: correctPubk,
			Ssig: ed25519.Sign(badSeck, staticPubk),
			Esig: ed25519.Sign(correctSeck, ephemeralPubk),
		},
	})
	err = hs.verifyRemoteSignatures()
	if assert.Error(t, err) {
		assert.Equal(t, &InvalidRemoteSignatureError{'s'}, err)
	}
}
