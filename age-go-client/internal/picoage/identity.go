package picoage

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"filippo.io/age"
	"github.com/Kacprucha/age-go-client/internal/device"
)

type PicoIdentity struct {
	Dev       *device.Device
	BypassTUP bool
}

type PicoIdentityFast struct {
	Dev       *device.Device
	BypassTUP bool
}

func (id *PicoIdentity) Unwrap(stanza []*age.Stanza) ([]byte, error) {
	for _, s := range stanza {
		if s.Type != "pico-p256" {
			continue
		}

		if len(s.Args) < 2 {
			continue
		}

		ephPub, err := base64.RawStdEncoding.DecodeString(s.Args[0])
		if err != nil || len(ephPub) != 65 {
			continue
		}

		slotInt, err := strconv.ParseUint(s.Args[1], 10, 8)
		if err != nil {
			continue
		}

		slot := uint8(slotInt)
		var shared []byte

		if id.BypassTUP {
			shared, err = id.Dev.ECDHBypassTUP(slot, ephPub[1:])
		} else {
			shared, err = id.Dev.ECDH(slot, ephPub[1:], 500*time.Millisecond)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to perform ECDH: %w", err)
		}

		devPub, err := id.Dev.GetPublicKey(slot)
		if err != nil {
			return nil, fmt.Errorf("failed to get device public key: %w", err)
		}

		kek := hkdfDerive(shared, ephPub, devPub, "age-encryption.org/v1/pico-p256")

		fileKey, err := chacha20Poly1305Unwrap(kek, s.Body)
		if err != nil {
			continue
		}
		return fileKey, nil
	}

	return nil, age.ErrIncorrectIdentity
}

func (id *PicoIdentityFast) Unwrap(stanza []*age.Stanza) ([]byte, error) {
	for _, s := range stanza {
		if s.Type != "pico-p256" {
			continue
		}

		if len(s.Args) < 2 {
			continue
		}

		ephPub, err := base64.RawStdEncoding.DecodeString(s.Args[0])
		if err != nil || len(ephPub) != 65 {
			continue
		}

		slotInt, err := strconv.ParseUint(s.Args[1], 10, 8)
		if err != nil {
			continue
		}
		slot := uint8(slotInt)

		shared, err := id.Dev.ECDHFast(slot, ephPub[1:])
		if err != nil {
			return nil, fmt.Errorf("failed to perform ECDH: %w", err)
		}

		devPub, err := id.Dev.GetPublicKey(slot)
		if err != nil {
			return nil, fmt.Errorf("failed to get device public key: %w", err)
		}

		kek := hkdfDerive(shared, ephPub, devPub, "age-encryption.org/v1/pico-p256")

		fileKey, err := chacha20Poly1305Unwrap(kek, s.Body)
		if err != nil {
			continue
		}
		return fileKey, nil
	}

	return nil, age.ErrIncorrectIdentity
}
