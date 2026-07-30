package main

import (
	"fmt"
	"os"

	"github.com/Kacprucha/age-go-client/cmd"
	"github.com/Kacprucha/age-go-client/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
)

const usage = `pico-crypt – file encryption with Pico + ATECC608A hardware key

Usage:
  pico-crypt                         Launch TUI (interactive interface)
  pico-crypt encrypt <plik> [--slot N]   Encrypt file (default slot 0)
  pico-crypt decrypt <plik.age>          Decrypt file (slot read from file)
  pico-crypt list-keys                   List available keys on the chip
  pico-crypt gen-key [--slot N]          Force key generation in slot N

Options:
  --slot N    ATECC608A slot number (0-7), default 0
  --port P    Pico serial port, default auto-detection /dev/ttyACM*
`

func main() {
	if len(os.Args) < 2 {
		p := tea.NewProgram(tui.InitialModel(), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	switch os.Args[1] {
	case "encrypt":
		cmd.RunEncrypt(os.Args[2:])
	case "decrypt":
		cmd.RunDecrypt(os.Args[2:])
	case "list-keys":
		cmd.RunListKeys(os.Args[2:])
	case "gen-key":
		cmd.RunGenKey(os.Args[2:])
	case "get-operation-time":
		cmd.RunGetOperationTime(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}
