package benchmarks

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/Kacprucha/age-go-client/internal/device"
	"github.com/Kacprucha/age-go-client/internal/picoage"
)

func BenchmarkECDH_Software(b *testing.B) {
	curve := ecdh.P256()
	priv, _ := curve.GenerateKey(rand.Reader)
	pub := priv.PublicKey()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eph, _ := curve.GenerateKey(rand.Reader)
		eph.ECDH(pub)
	}
}

func BenchmarkECDH_Hardware(b *testing.B) {
	dev, err := device.Open(device.Autodetect())
	if err != nil {
		b.Skip("Device not found, skipping hardware benchmark. Error: ", err)
	}
	defer dev.Close()

	devPub, err := dev.GetPublicKey(0)
	if err != nil {
		b.Skip("No key in slot 0, skipping hardware benchmark. Error: ", err)
	}

	curve := ecdh.P256()
	_ = devPub
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eph, _ := curve.GenerateKey(rand.Reader)
		dev.ECDH(0, eph.PublicKey().Bytes())
	}
}

var fileSize = []struct {
	name string
	size int
}{
	{"1KB", 1024},
	{"64KB", 64 * 1024},
	{"1MB", 1024 * 1024},
	{"10MB", 10 * 1024 * 1024},
}

func BenchmarkEncrypt_Soft(b *testing.B) {
	for _, sz := range fileSize {
		b.Run(sz.name, func(b *testing.B) {
			data := make([]byte, sz.size)
			rand.Read(data)
			key, _ := age.GenerateX25519Identity()
			b.SetBytes(int64(sz.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				enc, _ := age.Encrypt(&buf, key.Recipient())
				enc.Write(data)
				enc.Close()
			}
		})

	}
}

func BenchmarkEncrypt_Hardware(b *testing.B) {
	dev, err := device.Open(device.Autodetect())
	if err != nil {
		b.Skip("Device not found, skipping hardware benchmark. Error: ", err)
	}
	defer dev.Close()

	pub, err := dev.GetPublicKey(0)
	if err != nil {
		b.Skip("No key in slot 0, skipping hardware benchmark. Error: ", err)
	}

	r := &picoage.PicoRecipient{
		DevicePub: pub,
		Slot:      0,
	}

	for _, sz := range fileSize {
		b.Run(sz.name, func(b *testing.B) {
			data := make([]byte, sz.size)
			rand.Read(data)
			b.SetBytes(int64(sz.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				enc, _ := age.Encrypt(&buf, r)
				enc.Write(data)
				enc.Close()
			}
		})
	}
}

func BenchmarkDecrypt_Hardware(b *testing.B) {
	dev, err := device.Open(device.Autodetect())
	if err != nil {
		b.Skip("Device not found, skipping hardware benchmark. Error: ", err)
	}
	defer dev.Close()

	pub, err := dev.GetPublicKey(0)
	if err != nil {
		b.Skip("No key in slot 0, skipping hardware benchmark. Error: ", err)
	}

	data := make([]byte, 1024)
	rand.Read(data)

	r := &picoage.PicoRecipient{
		DevicePub: pub,
		Slot:      0,
	}

	var encBuf bytes.Buffer
	enc, _ := age.Encrypt(&encBuf, r)
	enc.Write(data)
	enc.Close()

	encData := encBuf.Bytes()

	identity := &picoage.PicoIdentity{Dev: dev}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _ := age.Decrypt(bytes.NewReader(encData), identity)
		io.Copy(io.Discard, r)
	}
}
