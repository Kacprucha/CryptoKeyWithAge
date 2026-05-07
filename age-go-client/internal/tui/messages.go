package tui

import (
	"fmt"

	"github.com/Kacprucha/age-go-client/internal/device"
	tea "github.com/charmbracelet/bubbletea"
)

type deviceConnectedMsg struct {
	port  string
	slots [8]bool
}

type deviceErrMsg struct{ err error }
type encryptDoneMsg struct{ outPath string }

type decryptDoneMsg struct {
	outPath    string
	ecdhMs     float64
	decryptMsg float64
}

type genKeyDoneMsg struct{ slot uint8 }
type errMsg struct{ err error }

func cmdConnectDevice() tea.Cmd {
	return func() tea.Msg {
		port := device.Autodetect()
		if port == "" {
			return deviceErrMsg{err: fmt.Errorf("no device found")}
		}

		dev, err := device.Open(port)
		if err != nil {
			return deviceErrMsg{err: err}
		}
		defer dev.Close()

		var slots [8]bool
		for i := 0; i < 8; i++ {
			_, err := dev.GetPublicKey(uint8(i))
			slots[i] = err == nil
		}

		return deviceConnectedMsg{port: port, slots: slots}
	}
}
