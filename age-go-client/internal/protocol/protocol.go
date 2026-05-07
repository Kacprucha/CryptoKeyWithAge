package protocol

const (
	Stx                    = 0x02
	CmdGetStatus           = 0x01
	CmdGetPublicKey        = 0x02
	CmdECDHRequest         = 0x03
	CmdGetRandom           = 0x04
	CmdGenKey              = 0x05
	CmdUserPresencePending = 0x06
)

const (
	StatusOK                     byte = 0x00
	StatusErrUnknownCmd          byte = 0x01 // ERR_UNKNOWN_CMD
	StatusErrBadCRC              byte = 0x02 // ERR_BAD_CRC
	StatusErrBadLength           byte = 0x03 // ERR_BAD_LENGTH
	StatusErrChipFail            byte = 0x04 // ERR_CHIP_FAIL
	StatusErrBadSlot             byte = 0x05 // ERR_BAD_SLOT
	StatusErrUserPresenceReq     byte = 0x06 // ERR_USER_PRESENCE_REQUIRED
	StatusErrUserPresenceTimeout byte = 0x07 // ERR_USER_PRESENCE_TIMEOUT
)

const (
	FrameHeaderSize = 4
	FrameCRCSize    = 4
	FrameOverhead   = FrameHeaderSize + FrameCRCSize
	MaxPayload      = 255
	TUPWindowMS     = 10000
)

const (
	PayloadGetPubKeyReq  = 1
	PayloadGetPubKeyResp = 64
	PayloadECDHReq       = 65
	PayloadECDHResp      = 32
	PayloadGenKeyReq     = 1
	PayloadGenKeyResp    = 64
)
