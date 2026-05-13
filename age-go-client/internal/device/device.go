package device

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Kacprucha/age-go-client/internal/protocol"
	"go.bug.st/serial"
)

var (
	ErrKeyNotFound = errors.New("key not found in slot")
	ErrTUPTimeout  = errors.New("timeout waiting for user presence")
)

const readTimeout = 15 * time.Second

type Device struct {
	port serial.Port
}

func Open(portName string) (*Device, error) {
	mode := &serial.Mode{BaudRate: 115200}
	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to open serial port: %w", err)
	}

	if err := port.SetReadTimeout(readTimeout); err != nil {
		port.Close()
		return nil, fmt.Errorf("failed to set read timeout: %w", err)
	}

	return &Device{port: port}, nil
}

func (d *Device) Close() {
	d.port.Close()
}

func Autodetect() string {
	matches, _ := filepath.Glob("/dev/ttyACM*")
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func mapFirmwareError(code byte) error {
	switch code {
	case protocol.StatusErrUnknownCmd:
		return fmt.Errorf("unknown commend")
	case protocol.StatusErrBadCRC:
		return fmt.Errorf("firmware rejected frame: CRC32 error")
	case protocol.StatusErrBadLength:
		return fmt.Errorf("firmware rejected frame: invalid length")
	case protocol.StatusErrChipFail:
		// ERR_CHIP_FAIL (0x04) returned when the slot is empty (ATCA_KEY_NOT_FOUND)
		// or when atcab_*() returns another error – treated as a missing key
		return ErrKeyNotFound
	case protocol.StatusErrBadSlot:
		return fmt.Errorf("invalid slot number (>7)")
	case protocol.StatusErrUserPresenceReq:
		return fmt.Errorf("pressing the TUP button is required")
	case protocol.StatusErrUserPresenceTimeout:
		return ErrTUPTimeout
	default:
		return fmt.Errorf("unknown firmware error: 0x%02X", code)
	}
}

func (d *Device) SendCmd(cmd byte, data []byte) ([]byte, error) {
	frame := buildFrame(cmd, data)
	if _, err := d.port.Write(frame); err != nil {
		return nil, fmt.Errorf("failed to write to device: %w", err)
	}
	return d.readResponse()
}

func (d *Device) SendCmdWithRetry(cmd byte, data []byte, maxRetries int) ([]byte, error) {
	err := errors.New("initial error")

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := d.SendCmd(cmd, data)
		if err == nil {
			return resp, nil
		}

		if errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrTUPTimeout) {
			return nil, err
		}

		if attempt < maxRetries-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("command failed after %d attempts: %w", maxRetries, err)
}

func (d *Device) GetPublicKey(slot uint8) ([]byte, error) {
	resp, err := d.SendCmd(protocol.CmdGetPublicKey, []byte{slot})

	if err != nil {
		return nil, fmt.Errorf("failed to get public key from slot %d: %w", slot, err)
	}

	if len(resp) != protocol.PayloadGetPubKeyResp {
		return nil, fmt.Errorf("unexpected public key length: expected %d bytes, got %d bytes", protocol.PayloadGetPubKeyResp, len(resp))
	}

	return resp, nil
}

func (d *Device) GenerateKey(slot uint8) ([]byte, error) {
	if slot > 7 {
		return nil, fmt.Errorf("invalid slot: %d", slot)
	}

	if err := d.flush(); err != nil {
		return nil, fmt.Errorf("flush befor GenerateKey: %w", err)
	}

	timeout := time.After(time.Duration(protocol.TUPWindowMS) * time.Millisecond)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return nil, ErrTUPTimeout
		case <-ticker.C:
			_ = d.flush()

			resp, err := d.SendCmd(protocol.CmdGenKey, []byte{slot})

			if err != nil {
				return nil, fmt.Errorf("GenerateKey retry (slot %d): %w", slot, err)
			}
			if len(resp) == protocol.PayloadGenKeyResp {
				return resp, nil
			}
		}
	}
}

// ECDHFast is a variant of ECDH with a shorter polling interval.
// // Use ONLY in benchmarks - in your application, use ECDH() with the default of 500ms.
func (d *Device) ECDHFast(slot uint8, theirPub []byte) ([]byte, error) {
	if len(theirPub) != 64 {
		return nil, fmt.Errorf("ECDH: invalid public key length: "+
			"expected 64 bytes, got %d bytes", len(theirPub))
	}

	payload := make([]byte, protocol.PayloadECDHReq)
	payload[0] = slot
	copy(payload[1:], theirPub)

	if err := d.flush(); err != nil {
		return nil, fmt.Errorf("flush przed ECDH: %w", err)
	}

	resp, err := d.SendCmd(protocol.CmdECDHRequest, payload)
	if err != nil {
		return nil, fmt.Errorf("ECDH init (slot %d): %w", slot, err)
	}

	if len(resp) == protocol.PayloadECDHResp {
		return resp, nil
	}

	timeout := time.After(time.Duration(protocol.TUPWindowMS) * time.Millisecond)

	for {
		select {
		case <-timeout:
			return nil, ErrTUPTimeout
		default:
			resp, err := d.SendCmd(protocol.CmdECDHRequest, payload)

			if err != nil {
				return nil, fmt.Errorf("ECDH poll (slot %d): %w", slot, err)
			}

			if len(resp) == protocol.PayloadECDHResp {
				return resp, nil
			}
		}
	}
}

func (d *Device) ECDH(slot uint8, theirPub []byte, pollInterval time.Duration) ([]byte, error) {

	if len(theirPub) != 64 {
		return nil, fmt.Errorf("ECDH: invalid public key length: "+
			"expected 64 bytes, got %d bytes", len(theirPub))
	}

	payload := make([]byte, protocol.PayloadECDHReq)
	payload[0] = slot
	copy(payload[1:], theirPub)

	if err := d.flush(); err != nil {
		return nil, fmt.Errorf("flush przed ECDH: %w", err)
	}

	resp, err := d.SendCmd(protocol.CmdECDHRequest, payload)
	if err != nil {
		return nil, fmt.Errorf("ECDH init (slot %d): %w", slot, err)
	}

	if len(resp) == protocol.PayloadECDHResp {
		return resp, nil
	}

	timeout := time.After(time.Duration(protocol.TUPWindowMS) * time.Millisecond)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastRespLen int = len(resp)

	for {
		select {
		case <-timeout:
			return nil, ErrTUPTimeout
		case <-ticker.C:
			_ = d.flush()
			resp, err := d.SendCmd(protocol.CmdECDHRequest, payload)

			if err != nil {
				return nil, fmt.Errorf("ECDH poll (slot %d): %w", slot, err)
			}

			if len(resp) == protocol.PayloadECDHResp {
				return resp, nil
			}

			if len(resp) != lastRespLen {
				resp2, err := d.SendCmd(protocol.CmdECDHRequest, payload)

				if err != nil {
					return nil, fmt.Errorf("ECDH fast-retry (slot %d): %w", slot, err)
				}

				if len(resp2) == protocol.PayloadECDHResp {
					return resp2, nil
				}
			}
			lastRespLen = len(resp)
		}
	}
}

func (d *Device) SendTUPRequest(slot uint8, theirPub []byte) error {
	payload := make([]byte, protocol.PayloadECDHReq)
	payload[0] = slot

	if len(theirPub) >= 64 {
		copy(payload[1:], theirPub[:64])
	}

	if err := d.flush(); err != nil {
		return err
	}

	d.SendCmd(protocol.CmdECDHRequest, payload)
	return nil
}

func (d *Device) flush() error {
	if err := d.port.SetReadTimeout(10 * time.Millisecond); err != nil {
		return err
	}

	buf := make([]byte, 256)

	for {
		n, _ := d.port.Read(buf)
		if n == 0 {
			break
		}
	}

	return d.port.SetReadTimeout(readTimeout)
}
