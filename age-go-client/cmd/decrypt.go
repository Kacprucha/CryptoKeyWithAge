package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/Kacprucha/age-go-client/internal/device"
	"github.com/Kacprucha/age-go-client/internal/picoage"
)

func RunDecrypt(args []string) {
	filePath, port := parseDecryptArgs(args)

	portPath := port
	if portPath == "" {
		portPath = device.Autodetect()
		if portPath == "" {
			fmt.Fprintln(os.Stderr, "Error: no device found")
			os.Exit(1)
		}
	}

	if err := ValidateInputFile(filePath, true); err != nil {
		fmt.Fprintf(os.Stderr, "Błąd walidacji: %v\n", err)
		os.Exit(1)
	}

	dev, err := device.Open(portPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening device: %v\n", err)
		os.Exit(1)
	}
	defer dev.Close()
	fmt.Printf("Using device on port: %s\n", portPath)

	identity := &picoage.PicoIdentity{Dev: dev}

	input, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer input.Close()

	fmt.Println("[!] Press button on device to autorize decryption...")
	r, err := age.Decrypt(input, identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting file: %v\n", err)
		fmt.Fprintln(os.Stderr, "Make sure the correct device is connected and the file was encrypted with a key from this device.")
		os.Exit(1)
	}

	outPath := strings.TrimSuffix(filePath, ".age")
	if outPath == filePath {
		outPath = filePath + ".dec"
	}

	output, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer output.Close()

	if _, err := io.Copy(output, r); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing decrypted file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decryption successful! Output file: %s\n", outPath)
}
