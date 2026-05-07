package picoage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func hkdfDerive(secret, ephPub, devPub []byte, label string) []byte {
	info := make([]byte, 0, len(ephPub)+len(devPub)+len(label))
	info = append(info, ephPub...)
	info = append(info, devPub...)
	info = append(info, []byte(label)...)

	r := hkdf.New(sha256.New, secret, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("failed to derive key: %v", err))
	}

	return key
}

func aesGCMWrap(kek, fileKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, fileKey, nil)
	return ciphertext, nil
}

func aesGCMUnwrap(kek, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
