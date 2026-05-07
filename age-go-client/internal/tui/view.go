package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	styleSelected = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleYellow   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleBox      = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("238")).
			Padding(0, 1)
	styleBoxGreen = styleBox.Copy().BorderForeground(lipgloss.Color("42"))
	styleBoxRed   = styleBox.Copy().BorderForeground(lipgloss.Color("196"))
)

var menuLabels = []string{
	"  Encrypt file",
	"  Decrypt file",
	"  Manage keys",
	"  Exit",
}

func (m Model) View() string {
	switch m.state {
	case stateConnecting:
		return m.viewConnecting()
	case stateMenu:
		return m.viewMenu()
	case stateFilePicker:
		return m.viewFilePicker()
	case stateSlotSelect:
		return m.viewSlotSelect()
	case stateTUPWaiting:
		return m.viewTUP()
	case stateProgress:
		return m.viewProgress()
	case stateDone:
		return m.viewDone()
	case stateKeyMgmt:
		return m.viewKeyMgmt()
	case stateError:
		return m.viewError()
	}
	return ""
}

func (m Model) viewConnecting() string {
	return fmt.Sprintf("\n  %s  %s\n\n  %s\n",
		m.spinner.View(),
		styleTitle.Render("pico-crypt"),
		styleDim.Render("Pico Device Detection..."),
	)
}

func (m Model) viewMenu() string {
	var b strings.Builder
	b.WriteString("\n  " + styleTitle.Render("pico-crypt") +
		"  " + styleDim.Render("v1.0.0 · hardware encryption") + "\n\n")

	activeCount := 0
	for _, has := range m.slots {
		if has {
			activeCount++
		}
	}

	if m.deviceOK {
		status := styleGreen.Render("● Connected") + styleDim.Render("  "+m.devicePort) + "\n  " +
			styleDim.Render(fmt.Sprintf("ATECC608A · %d active / %d empty", activeCount, 8-activeCount))
		b.WriteString(styleBoxGreen.Render(status) + "\n\n")
	} else {
		b.WriteString(styleBoxRed.Render(
			styleRed.Render("✗ No device")+"\n  "+
				styleDim.Render("Connect Pico to USB")) + "\n\n")
	}

	for i, label := range menuLabels {
		if i == m.cursor {
			b.WriteString("  " + styleSelected.Render("› "+label) + "\n")
		} else {
			b.WriteString("  " + styleDim.Render("  "+label) + "\n")
		}
	}
	b.WriteString("\n  " + styleDim.Render("↑↓/jk navigation  ·  enter choose  ·  q exit"))
	return b.String()
}

func (m Model) viewTUP() string {
	action := "authorize decryption"
	warning := ""
	if m.pendingOp == opGenKey {
		action = "authorize KEY GENERATION"
		warning = "\n\n  " + styleRed.Render("⚠ Irreversible operation - the old key will be destroyed")
	}

	barWidth := 30
	filled := int(float64(m.tupRemaining) / 10.0 * float64(barWidth))
	bar := styleYellow.Render(strings.Repeat("█", filled)) +
		styleDim.Render(strings.Repeat("░", barWidth-filled))
	return fmt.Sprintf(
		"\n  %s  %s\n\n  %s\n\n  %s\n\n  %s  %s\n\n  %s\n\n  %s\n",
		styleYellow.Render("●"),
		styleYellow.Render("Tap the button on your Pico device"),
		styleYellow.Render(action+warning),
		styleDim.Render("Test of User Presence (TUP) · FIDO U2F"),
		bar, styleDim.Render(fmt.Sprintf("%ds", m.tupRemaining)),
		styleDim.Render("File: "+m.selectedFile),
		styleDim.Render("esc cancel"),
	)
}

func (m Model) viewSlotSelect() string {
	var slots strings.Builder
	for i := 0; i <= 7; i++ {
		label := fmt.Sprintf(" %d ", i)
		switch {
		case uint8(i) == m.activeSlot:
			slots.WriteString(styleSelected.Render("["+label+"]") + " ")
		case m.slots[i]:
			slots.WriteString(styleGreen.Render("("+label+")") + " ")
		default:
			slots.WriteString(styleDim.Render(" "+label+" ") + " ")
		}
	}
	return fmt.Sprintf("\n  %s\n\n  %s\n  %s\n\n  %s\n\n  %s\n",
		styleTitle.Render("Select a slot ATECC608A"),
		styleDim.Render("File: "+m.selectedFile),
		slots.String(),
		styleDim.Render("[x] chosen  ( ) active key   empty without brackets"),
		styleDim.Render("←→/hl change  ·  enter encrypt  ·  esc exit"),
	)
}

func (m Model) viewFilePicker() string {
	header := "\n  "
	filterInfo := ""

	if m.mode == modeEncrypt {
		header += styleTitle.Render("Select the file to encrypt")
		filterInfo = styleDim.Render("  all files")
	} else {
		header += styleTitle.Render("Select the .age file to decrypt")
		filterInfo = styleYellow.Render("  filter: ") + styleGreen.Render(".age")
	}

	help := styleDim.Render("↑↓/jk") + " " + styleDim.Render("navigation") +
		"  " + styleDim.Render("←/h") + " " + styleDim.Render("undo") +
		"  " + styleDim.Render("→/l/enter") + " " + styleDim.Render("open") +
		"  " + styleDim.Render("esc") + " " + styleDim.Render("back to menu")

	// Aktualny katalog
	currentDir := m.filepicker.CurrentDirectory
	dirLine := styleDim.Render("  📁 "+currentDir) + filterInfo

	return header + "\n" + dirLine + "\n\n" +
		m.filepicker.View() +
		"\n\n  " + help
}

func (m Model) viewProgress() string {
	return fmt.Sprintf("\n  %s  %s\n\n  %s\n",
		m.spinner.View(),
		styleTitle.Render("Operation in progress..."),
		styleDim.Render("File: "+m.selectedFile),
	)
}

func (m Model) viewDone() string {
	var b strings.Builder
	b.WriteString("\n  " + styleGreen.Render("✓ The operation was completed successfully") + "\n\n")
	details := fmt.Sprintf("  Output:  %s\n  ECDH:     %.1f ms\n  Decrypt:  %.2f ms",
		m.outputFile, m.resultInfo.ecdhMs, m.resultInfo.decryptMs)
	b.WriteString(styleBox.Render(details) + "\n\n")
	b.WriteString("  " + styleDim.Render("enter / esc back to menu"))
	return b.String()
}

func (m Model) viewKeyMgmt() string {
	var b strings.Builder
	b.WriteString("\n  " + styleTitle.Render("ATECC608A key management") + "\n\n")
	var slots strings.Builder
	for i := 0; i <= 7; i++ {
		label := fmt.Sprintf(" %d ", i)
		switch {
		case uint8(i) == m.activeSlot:
			slots.WriteString(styleSelected.Render("["+label+"]") + " ")
		case m.slots[i]:
			slots.WriteString(styleGreen.Render("("+label+")") + " ")
		default:
			slots.WriteString(styleDim.Render(" "+label+" ") + " ")
		}
	}
	b.WriteString("  " + slots.String() + "\n\n")
	if m.slots[m.activeSlot] {
		b.WriteString("  " + styleGreen.Render(fmt.Sprintf("Slot %d: active", m.activeSlot)) + "\n")
	} else {
		b.WriteString("  " + styleDim.Render(fmt.Sprintf("Slot %d: empty", m.activeSlot)) + "\n")
	}
	b.WriteString("\n  " + styleDim.Render("←→/hl change  ·  g key generation  ·  esc exit"))
	return b.String()
}

func (m Model) viewError() string {
	errText := "unknown error"
	if m.err != nil {
		errText = m.err.Error()
	}
	return fmt.Sprintf("\n  %s\n\n%s\n\n  %s\n",
		styleRed.Render("✗ Error"),
		styleBoxRed.Render("  "+errText),
		styleDim.Render("enter / esc back to menu"),
	)
}
