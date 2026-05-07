package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/Kacprucha/age-go-client/internal/device"
	"github.com/Kacprucha/age-go-client/internal/picoage"
)

func RunEncrypt(args []string) {
	filePath, slot, port := parseEncryptArgs(args)

	portPath := port
	if portPath == "" {
		portPath = device.Autodetect()
		if portPath == "" {
			fmt.Fprintln(os.Stderr, "Error: no device found")
			os.Exit(1)
		}
	}

	if err := ValidateInputFile(filePath, false); err != nil {
		fmt.Fprintf(os.Stderr, "Error in validation: %v\n", err)
		os.Exit(1)
	}

	dev, err := device.Open(portPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening device: %v\n", err)
		os.Exit(1)
	}
	defer dev.Close()
	fmt.Printf("Using device on port: %s\n", portPath)

	pub, err := dev.GetPublicKey(slot)
	if errors.Is(err, device.ErrKeyNotFound) {
		fmt.Printf("No key in slot %d, generating new key...\n", slot)

		if !askConfirm(fmt.Sprintf("Generate new key in slot %d?", slot)) {
			fmt.Println("Aborting.")
			os.Exit(0)
		}

		pub, err = dev.GenerateKey(slot)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving public key: %v\n", err)
		os.Exit(1)
	}

	recipient := &picoage.PicoRecipient{
		DevicePub: pub,
		Slot:      slot,
	}

	input, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
		os.Exit(1)
	}
	defer input.Close()

	outPath := filePath + ".age"
	output, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer output.Close()

	w, err := age.Encrypt(output, recipient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing encryption: %v\n", err)
		os.Exit(1)
	}

	if _, err := io.Copy(w, input); err != nil {
		fmt.Fprintf(os.Stderr, "Error during encryption: %v\n", err)
		os.Exit(1)
	}

	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error finalizing encryption: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File encrypted successfully: %s\n", outPath)
}

func askConfirm(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
