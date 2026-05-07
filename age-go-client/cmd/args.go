package cmd

import (
	"fmt"
	"os"
	"strconv"
)

func parseEncryptArgs(args []string) (filePath string, slot uint8, port string) {
	slot = 0

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--slot":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --slot flag requires a value")
				os.Exit(1)
			}

			i++
			n, err := strconv.ParseUint(args[i], 10, 8)

			if err != nil || n > 7 {
				fmt.Fprintf(os.Stderr, "Error: invalid slot number '%s'. Must be an integer between 0 and 7.\n", args[i])
				os.Exit(1)
			}

			slot = uint8(n)

		case "--port":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --port flag requires a value")
				os.Exit(1)
			}

			i++
			port = args[i]

		default:
			if filePath == "" {
				filePath = args[i]
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: missing file path argument")
		fmt.Fprintln(os.Stderr, "Usage: age-go-client encrypt <file> [--slot <0-7>] [--port <device>]")
		os.Exit(1)
	}

	return
}

func parseDecryptArgs(args []string) (filePath string, port string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --port flag requires a value")
				os.Exit(1)
			}

			i++
			port = args[i]

		default:
			if filePath == "" {
				filePath = args[i]
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: missing file path argument")
		fmt.Fprintln(os.Stderr, "Usage: age-go-client decrypt <file> [--port <device>]")
		os.Exit(1)
	}

	return
}

func parseListArgs(args []string) (unused string, port string) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			i++
			port = args[i]
		}
	}

	return
}

func parseGenKeyArgs(args []string) (slot uint8, port string) {
	slot = 0

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--slot":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --slot flag requires a value")
				os.Exit(1)
			}

			i++
			n, err := strconv.ParseUint(args[i], 10, 8)

			if err != nil || n > 7 {
				fmt.Fprintf(os.Stderr, "Error: invalid slot number '%s'. Must be an integer between 0 and 7.\n", args[i])
				os.Exit(1)
			}

			slot = uint8(n)

		case "--port":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --port flag requires a value")
				os.Exit(1)
			}

			i++
			port = args[i]
		}
	}

	return
}
