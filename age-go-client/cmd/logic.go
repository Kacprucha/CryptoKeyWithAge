package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/Kacprucha/age-go-client/internal/device"
	"github.com/Kacprucha/age-go-client/internal/picoage"
)

// EncryptFile szyfruje plik używając klucza pub z podanego slotu.
// Wywoływana przez RunEncrypt() (CLI) i cmdEncryptAsync() (TUI).
func EncryptFile(filePath string, slot uint8, pub []byte) (string, error) {
	recipient := &picoage.PicoRecipient{DevicePub: pub, Slot: slot}
	input, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer input.Close()

	outPath := filePath + ".age"
	output, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer output.Close()

	w, err := age.Encrypt(output, recipient)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(w, input); err != nil {
		return "", err
	}
	return outPath, w.Close()
}

// DecryptFile odszyfrowuje plik .age przez Pico.
// Zwraca ścieżkę wyniku i czasy operacji (wyświetlane w TUI na ekranie stateDone).
func DecryptFile(filePath string, dev *device.Device) (outPath string, ecdhMs, decryptMs float64, err error) {
	identity := &picoage.PicoIdentity{Dev: dev}
	input, err := os.Open(filePath)
	if err != nil {
		return "", 0, 0, err
	}
	defer input.Close()

	t0 := time.Now()
	r, err := age.Decrypt(input, identity)
	if err != nil {
		return "", 0, 0, err
	}
	ecdhMs = float64(time.Since(t0).Milliseconds())

	outPath = strings.TrimSuffix(filePath, ".age")
	if outPath == filePath {
		outPath = filePath + ".dec"
	}

	output, err := os.Create(outPath)
	if err != nil {
		return "", 0, 0, err
	}
	defer output.Close()

	t1 := time.Now()
	if _, err := io.Copy(output, r); err != nil {
		return "", 0, 0, err
	}
	decryptMs = float64(time.Since(t1).Milliseconds())
	return outPath, ecdhMs, decryptMs, nil
}

func RunGenKey(args []string) {
	slot, port := parseGenKeyArgs(args)

	portPath := port
	if portPath == "" {
		portPath = device.Autodetect()
		if portPath == "" {
			fmt.Fprintln(os.Stderr, "Error: no device found")
			os.Exit(1)
		}
	}

	dev, err := device.Open(portPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening device: %v\n", err)
		os.Exit(1)
	}
	defer dev.Close()

	fmt.Printf("Using device on port: %s\n", portPath)

	pub, err := dev.GenerateKey(slot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated key in slot %d with public key: %x\n", slot, pub)
}
