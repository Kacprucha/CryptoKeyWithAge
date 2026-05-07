package tui

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Kacprucha/age-go-client/cmd"
	"github.com/Kacprucha/age-go-client/internal/device"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type tupTickMsg struct{}

func tupTick() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg { return tupTickMsg{} })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.state == stateFilePicker {
		if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "esc" {
			m.state = stateMenu
			return m, nil
		}

		var c tea.Cmd
		m.filepicker, c = m.filepicker.Update(msg)

		if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
			fmt.Fprintf(os.Stderr, "DEBUG selected: %q mode=%d\n", path, m.mode)

			if err := cmd.ValidateInputFile(path, m.mode == modeDecrypt); err != nil {
				m.err = err
				m.state = stateError
				return m, nil
			}

			m.selectedFile = path
			if m.mode == modeDecrypt {
				m.state, m.tupRemaining, m.pendingOp = stateTUPWaiting, 10, opECDH
				return m, tea.Batch(tupTick(), cmdDecryptAsync(path, m.devicePort))
			}
			m.state = stateSlotSelect
		}

		return m, c
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case stateMenu:
			return m.updateMenu(msg)
		case stateFilePicker:
			return m.updateFilePicker(msg)
		case stateSlotSelect:
			return m.updateSlotSelect(msg)
		case stateTUPWaiting:
			if msg.String() == "esc" {
				m.state = stateMenu
				return m, nil
			}
		case stateDone, stateError:
			if msg.String() == "enter" || msg.String() == "esc" {
				m.state = stateMenu
				return m, nil
			}
		case stateKeyMgmt:
			return m.updateKeyMgmt(msg)
		}

		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case deviceConnectedMsg:
		m.deviceOK, m.devicePort, m.slots = true, msg.port, msg.slots
		m.state = stateMenu

	case deviceErrMsg:
		m.deviceOK, m.err, m.state = false, msg.err, stateError

	case encryptDoneMsg:
		m.outputFile, m.state = msg.outPath, stateDone

	case decryptDoneMsg:
		m.outputFile = msg.outPath
		m.resultInfo = resultInfo{ecdhMs: msg.ecdhMs, decryptMs: msg.decryptMsg, tupOK: true}
		m.state = stateDone

	case genKeyDoneMsg:
		m.slots[msg.slot], m.state = true, stateKeyMgmt

	case errMsg:
		m.err, m.state = msg.err, stateError

	case tupTickMsg:
		if m.state == stateTUPWaiting {
			m.tupRemaining--
			if m.tupRemaining > 0 {
				return m, tupTick()
			}
		}

	case spinner.TickMsg:
		var c tea.Cmd
		m.spinner, c = m.spinner.Update(msg)
		return m, c
	}
	return m, nil
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 3 {
			m.cursor++
		}
	case "enter":
		return m.activateMenuItem()
	case "e":
		m.cursor = 0
		return m.activateMenuItem()
	case "d":
		m.cursor = 1
		return m.activateMenuItem()
	case "q", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) activateMenuItem() (Model, tea.Cmd) {
	switch m.cursor {
	case 0:
		m.mode = modeEncrypt
		m.filepicker.AllowedTypes = []string{} // empty = all extensions
		m.filepicker.AutoHeight = false
		m.state = stateFilePicker
		return m, m.filepicker.Init()
	case 1:
		m.mode = modeDecrypt
		m.filepicker.AllowedTypes = []string{".age"}
		m.filepicker.ShowPermissions = false
		m.filepicker.ShowSize = true
		m.filepicker.AutoHeight = false
		m.state = stateFilePicker
	case 2:
		m.state = stateKeyMgmt
	case 3:
		return m, tea.Quit
	}
	return m, m.filepicker.Init()
}

func (m Model) updateSlotSelect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h":
		if m.activeSlot > 0 {
			m.activeSlot--
		}
	case "right", "l":
		if m.activeSlot < 7 {
			m.activeSlot++
		}
	case "enter":
		m.state = stateProgress
		return m, cmdEncryptAsync(m.selectedFile, m.activeSlot, m.devicePort)
	case "esc":
		m.state = stateFilePicker
	}
	return m, nil
}

func (m Model) updateKeyMgmt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h":
		if m.activeSlot > 0 {
			m.activeSlot--
		}
	case "right", "l":
		if m.activeSlot < 7 {
			m.activeSlot++
		}
	case "g":
		m.state = stateTUPWaiting
		m.tupRemaining = 10
		m.pendingOp = opGenKey
		return m, tea.Batch(tupTick(), cmdGenKeyAsync(m.activeSlot, m.devicePort))
	case "esc", "q":
		m.state = stateMenu
	}
	return m, nil
}

func (m Model) updateFilePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.state = stateMenu
		return m, nil
	}
	var c tea.Cmd
	m.filepicker, c = m.filepicker.Update(msg)
	if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
		if err := cmd.ValidateInputFile(path, m.mode == modeDecrypt); err != nil {
			m.err = err
			m.state = stateError
			return m, nil
		}

		m.selectedFile = path

		if m.mode == modeDecrypt {
			m.state, m.tupRemaining, m.pendingOp = stateTUPWaiting, 10, opECDH
			return m, tea.Batch(tupTick(), cmdDecryptAsync(path, m.devicePort))
		}

		m.state = stateSlotSelect
	}
	return m, c
}

func cmdEncryptAsync(filePath string, slot uint8, port string) tea.Cmd {
	return func() tea.Msg {
		dev, err := device.Open(port)
		if err != nil {
			return errMsg{err: fmt.Errorf("connection error: %w", err)}
		}
		defer dev.Close()

		pub, err := dev.GetPublicKey(slot)
		if errors.Is(err, device.ErrKeyNotFound) {
			pub, err = dev.GenerateKey(slot)
		}
		if err != nil {
			return errMsg{err: err}
		}

		outPath, err := cmd.EncryptFile(filePath, slot, pub)
		if err != nil {
			return errMsg{err: err}
		}
		return encryptDoneMsg{outPath: outPath}
	}
}

func cmdDecryptAsync(filePath string, port string) tea.Cmd {
	return func() tea.Msg {
		dev, err := device.Open(port)
		if err != nil {
			return errMsg{err: fmt.Errorf("connection error: %w", err)}
		}
		defer dev.Close()

		outPath, ecdhMs, decryptMs, err := cmd.DecryptFile(filePath, dev)
		if err != nil {
			return errMsg{err: err}
		}
		return decryptDoneMsg{outPath: outPath, ecdhMs: ecdhMs, decryptMsg: decryptMs}
	}
}

func cmdGenKeyAsync(slot uint8, port string) tea.Cmd {
	return func() tea.Msg {
		dev, err := device.Open(port)
		if err != nil {
			return errMsg{err: fmt.Errorf("connection error: %w", err)}
		}
		defer dev.Close()
		if _, err := dev.GenerateKey(slot); err != nil {
			return errMsg{err: err}
		}
		return genKeyDoneMsg{slot: slot}
	}
}
