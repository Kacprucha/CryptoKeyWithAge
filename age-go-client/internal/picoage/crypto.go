package picoage

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func hkdfDerive(secret, ephPub, devPub []byte, label string) []byte {
	salt := make([]byte, 0, len(ephPub)+len(devPub))
	salt = append(salt, ephPub...)
	salt = append(salt, devPub...)

	r := hkdf.New(sha256.New, secret, salt, []byte(label))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("failed to derive key: %v", err))
	}

	return key
}

func chacha20Poly1305Wrap(kek, fileKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, fileKey, nil), nil
}

func chacha20Poly1305Unwrap(kek, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}
