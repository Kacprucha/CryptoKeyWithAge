package cmd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/Kacprucha/age-go-client/internal/device"
)

func RunListKeys(args []string) {
	_, port := parseListArgs(args)

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

	fmt.Println("Keys on ATECC608A device:")
	fmt.Println("Slot\tStatus\tFingerprint")
	fmt.Println("----\t------\t" + strings.Repeat("-", 64))

	for slot := uint8(0); slot <= 7; slot++ {
		pub, err := dev.GetPublicKey(slot)
		if err != nil {
			fmt.Printf("%d\tEmpty\t%s\n", slot, strings.Repeat("-", 64))
			continue
		}

		h := sha256.Sum256(pub)
		fmt.Printf("%d\t[Available]\t%x\n", slot, h[:8])
	}
}
