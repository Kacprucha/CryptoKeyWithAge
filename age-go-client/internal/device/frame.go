package device

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/Kacprucha/age-go-client/internal/protocol"
)

func crc32ieee(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func buildFrame(cmd byte, data []byte) []byte {
	dataLen := len(data)

	frame := make([]byte, protocol.FrameHeaderSize+dataLen+protocol.FrameCRCSize)
	frame[0] = protocol.Stx
	frame[1] = cmd

	binary.LittleEndian.PutUint16(frame[2:4], uint16(dataLen))
	copy(frame[4:4+dataLen], data)

	crc := crc32ieee(frame[:4+dataLen])
	binary.LittleEndian.PutUint32(frame[4+dataLen:], crc)

	return frame
}

func (d *Device) readResponse() ([]byte, error) {
	header := make([]byte, protocol.FrameHeaderSize)
	if _, err := io.ReadFull(d.port, header); err != nil {
		return nil, fmt.Errorf("failed to read frame header: %w", err)
	}

	if header[0] != protocol.Stx {
		return nil, fmt.Errorf("invalid start byte: expected 0x02, got 0x%02x", header[0])
	}

	status := header[1]
	dataLen := binary.LittleEndian.Uint16(header[2:4])

	if dataLen > protocol.MaxPayload {
		return nil, fmt.Errorf("payload too large: %d bytes", dataLen)
	}

	data := make([]byte, dataLen)
	if dataLen > 0 {
		if _, err := io.ReadFull(d.port, data); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	crcBuf := make([]byte, protocol.FrameCRCSize)
	if _, err := io.ReadFull(d.port, crcBuf); err != nil {
		return nil, fmt.Errorf("failed to read CRC: %w", err)
	}
	receivedCRC := binary.LittleEndian.Uint32(crcBuf)

	crcInput := make([]byte, protocol.FrameHeaderSize+int(dataLen))
	copy(crcInput, header)
	copy(crcInput[protocol.FrameHeaderSize:], data)
	expectedCRC := crc32ieee(crcInput)

	if receivedCRC != expectedCRC {
		return nil, fmt.Errorf("CRC mismatch: expected 0x%08x, got 0x%08x", expectedCRC, receivedCRC)
	}

	if status == 0xFF {
		if len(data) == 0 {
			return nil, fmt.Errorf("firmware error: no error code in payload")
		}
		return nil, mapFirmwareError(data[0])
	}

	return data, nil
}
