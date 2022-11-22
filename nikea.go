package nikea

import "fmt"

const SharedSecret = "SHARED_SECRET"

type KeyPair struct {
	SecretKey []byte
	PublicKey []byte
}

type InvalidRemoteSignatureError struct {
	key byte
}

func (e *InvalidRemoteSignatureError) Error() string {
	return fmt.Sprintf("Signature validation failed for key: %q", e.key)
}

type IllegalCryptoOperation struct {
	mode CipherStateMode
}

func (e *IllegalCryptoOperation) Error() string {
	return fmt.Sprintf("Operation not allowed with mode: %q", e.mode)
}
