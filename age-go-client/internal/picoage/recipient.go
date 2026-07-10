package picoage

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
)

type PicoRecipient struct {
	DevicePub []byte
	Slot      uint8
}

func (r *PicoRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	curve := ecdh.P256()

	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephPub := ephPriv.PublicKey().Bytes()

	if len(r.DevicePub) != 64 {
		return nil, fmt.Errorf("invalid device public key: expected 64B, got %dB", len(r.DevicePub))
	}
	devPubBytes := make([]byte, 65)
	devPubBytes[0] = 0x04
	copy(devPubBytes[1:], r.DevicePub)

	devPub, err := curve.NewPublicKey(devPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid device public key: %w", err)
	}

	shared, err := ephPriv.ECDH(devPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	kek := hkdfDerive(shared, ephPub, r.DevicePub, "age-encryption.org/v1/pico-p256")

	encFileKey, err := chacha20Poly1305Wrap(kek, fileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap file key: %w", err)
	}

	stanza := &age.Stanza{
		Type: "pico-p256",
		Args: []string{
			base64.RawStdEncoding.EncodeToString(ephPub),
			fmt.Sprintf("%d", r.Slot),
		},
		Body: encFileKey,
	}

	return []*age.Stanza{stanza}, nil
}
