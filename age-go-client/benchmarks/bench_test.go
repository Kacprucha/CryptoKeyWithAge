package benchmarks

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/Kacprucha/age-go-client/internal/device"
	"github.com/Kacprucha/age-go-client/internal/picoage"
)

var fileSizes = []struct {
	name string
	size int
}{
	{"100B", 100},
	{"1KB", 1024},
	{"64KB", 64 * 1024},
	{"1MB", 1024 * 1024},
	{"10MB", 10 * 1024 * 1024},
	{"100MB", 100 * 1024 * 1024},
}

type ageSizes struct {
	EncryptedBytes int64
	OverheadBytes  int64
	HeaderBytes    int64
	PayloadBytes   int64
}

func measureAgeSoftSize(data []byte) ageSizes {
	key, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	enc, _ := age.Encrypt(&buf, key.Recipient())
	enc.Write(data)
	enc.Close()
	encData := buf.Bytes()
	encTotal := int64(len(encData))
	headerEnd := findAgeHeaderEnd(encData)
	return ageSizes{
		EncryptedBytes: encTotal,
		OverheadBytes:  encTotal - int64(len(data)),
		HeaderBytes:    headerEnd,
		PayloadBytes:   encTotal - headerEnd,
	}
}

func measureAgeHardwareSize(data []byte, r *picoage.PicoRecipient) ageSizes {
	var buf bytes.Buffer
	enc, _ := age.Encrypt(&buf, r)
	enc.Write(data)
	enc.Close()
	encData := buf.Bytes()
	encTotal := int64(len(encData))
	headerEnd := findAgeHeaderEnd(encData)
	return ageSizes{
		EncryptedBytes: encTotal,
		OverheadBytes:  encTotal - int64(len(data)),
		HeaderBytes:    headerEnd,
		PayloadBytes:   encTotal - headerEnd,
	}
}

func findAgeHeaderEnd(data []byte) int64 {
	for i := 1; i < len(data)-3; i++ {
		if data[i] == '\n' && data[i+1] == '-' &&
			data[i+2] == '-' && data[i+3] == '-' {
			for j := i + 3; j < len(data); j++ {
				if data[j] == '\n' {
					return int64(j + 1)
				}
			}
		}
	}
	return 0
}

func encryptSoft(data []byte) ([]byte, *age.X25519Identity) {
	key, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	enc, _ := age.Encrypt(&buf, key.Recipient())
	enc.Write(data)
	enc.Close()
	return buf.Bytes(), key
}

func encryptHardware(data []byte, r *picoage.PicoRecipient) []byte {
	var buf bytes.Buffer
	enc, _ := age.Encrypt(&buf, r)
	enc.Write(data)
	enc.Close()
	return buf.Bytes()
}

// ECDH Benchmarki

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
		b.Skip("Device not found: ", err)
	}
	defer dev.Close()

	_, err = dev.GetPublicKey(0)

	if err != nil {
		b.Skip("No key in slot 0: ", err)
	}

	curve := ecdh.P256()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eph, _ := curve.GenerateKey(rand.Reader)
		pub := eph.PublicKey().Bytes()
		dev.ECDHBypassTUP(0, pub[1:])
	}
}

// Encrypt Benchmarki

// BenchmarkEncrypt_Hardware
func BenchmarkEncrypt_Hardware(b *testing.B) {
	dev, err := device.Open(device.Autodetect())

	if err != nil {
		b.Skip("Device not found: ", err)
	}

	defer dev.Close()
	pub, err := dev.GetPublicKey(0)

	if err != nil {
		b.Skip("No key in slot 0: ", err)
	}

	r := &picoage.PicoRecipient{DevicePub: pub, Slot: 0}
	for _, sz := range fileSizes {
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

// Decrypt Benchmarki
func BenchmarkDecrypt_Hardware(b *testing.B) {
	dev, err := device.Open(device.Autodetect())

	if err != nil {
		b.Skip("Device not found: ", err)
	}
	defer dev.Close()

	pub, err := dev.GetPublicKey(0)
	if err != nil {
		b.Skip("No key in slot 0: ", err)
	}

	r := &picoage.PicoRecipient{DevicePub: pub, Slot: 0}
	identity := &picoage.PicoIdentity{Dev: dev, BypassTUP: true}

	for _, sz := range fileSizes {
		b.Run(sz.name, func(b *testing.B) {
			data := make([]byte, sz.size)
			rand.Read(data)
			encData := encryptHardware(data, r)

			b.SetBytes(int64(sz.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				r, err := age.Decrypt(bytes.NewReader(encData), identity)
				if err != nil {
					b.Fatal("decrypt error:", err)
				}
				io.Copy(io.Discard, r)
			}
		})
	}
}

// File size measurements
func TestFileSizes(t *testing.T) {
	fmt.Println("format,variant,size_name,plaintext_bytes," +
		"encrypted_bytes,overhead_bytes,header_bytes,payload_bytes")

	for _, sz := range fileSizes {
		data := make([]byte, sz.size)

		for i := range data {
			data[i] = byte(i & 0xFF)
		}

		s := measureAgeSoftSize(data)
		fmt.Printf("age,Software,%s,%d,%d,%d,%d,%d\n",
			sz.name, sz.size,
			s.EncryptedBytes, s.OverheadBytes,
			s.HeaderBytes, s.PayloadBytes)
	}

	dev, err := device.Open(device.Autodetect())
	if err != nil {
		t.Log("Pico nie znalezione — pomijam pomiary hardware")
		return
	}
	defer dev.Close()

	pub, err := dev.GetPublicKey(0)
	if err != nil {
		t.Log("Brak klucza w slot 0 — pomijam hardware")
		return
	}

	r := &picoage.PicoRecipient{DevicePub: pub, Slot: 0}
	for _, sz := range fileSizes {
		data := make([]byte, sz.size)
		for i := range data {
			data[i] = byte(i & 0xFF)
		}
		s := measureAgeHardwareSize(data, r)
		fmt.Printf("age,Hardware[soft-ECDH],%s,%d,%d,%d,%d,%d\n",
			sz.name, sz.size,
			s.EncryptedBytes, s.OverheadBytes,
			s.HeaderBytes, s.PayloadBytes)
	}
}
