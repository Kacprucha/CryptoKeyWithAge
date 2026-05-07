package tui

import (
	"os"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type appState int

const (
	stateConnecting appState = iota
	stateMenu
	stateFilePicker
	stateSlotSelect
	stateTUPWaiting
	stateProgress
	stateDone
	stateKeyMgmt
	stateError
)

type operationMode int

const (
	modeEncrypt operationMode = iota
	modeDecrypt
	modeGenKey
)

type pendingOp int

const (
	opGenKey pendingOp = iota
	opECDH
)

type Model struct {
	state appState
	mode  operationMode
	pendingOp
	cursor     int
	devicePort string
	deviceOK   bool
	slots      [8]bool
	activeSlot uint8

	selectedFile string
	outputFile   string
	resultInfo   resultInfo

	filepicker   filepicker.Model
	spinner      spinner.Model
	progress     progress.Model
	tupRemaining int
	err          error
}

type resultInfo struct {
	ecdhMs    float64
	decryptMs float64
	fileSizeB int64
	tupOK     bool
}

func InitialModel() Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot

	fp := filepicker.New()
	fp.CurrentDirectory, _ = os.UserHomeDir()
	fp.ShowHidden = false
	fp.SetHeight(15)
	fp.KeyMap = filepicker.KeyMap{
		GoToTop:  key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "first")),
		GoToLast: key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "last")),
		Down:     key.NewBinding(key.WithKeys("j", "down"), key.WithHelp("↓/j", "down")),
		Up:       key.NewBinding(key.WithKeys("k", "up"), key.WithHelp("↑/k", "up")),
		PageUp:   key.NewBinding(key.WithKeys("K", "pgup"), key.WithHelp("pgup", "page up")),
		PageDown: key.NewBinding(key.WithKeys("J", "pgdn"), key.WithHelp("pgdn", "page down")),
		Back:     key.NewBinding(key.WithKeys("h", "left"), key.WithHelp("←/h", "back")),
		Open:     key.NewBinding(key.WithKeys("l", "right", "enter"), key.WithHelp("→/l", "open")),
		Select:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
	}

	pb := progress.New(progress.WithDefaultGradient())

	return Model{
		state:        stateConnecting,
		spinner:      sp,
		filepicker:   fp,
		progress:     pb,
		tupRemaining: 10,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, cmdConnectDevice())
}
