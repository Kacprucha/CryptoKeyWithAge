Request frame (host → Pico): [0x02][CMD][LEN_LO][LEN_HI][...DATA...][CRC_0][CRC_1][CRC_2][CRC_3] 

Respone frame (Pico → host): [0x02][CMD|0x80][LEN_LO][LEN_HI][...DATA...][CRC_0][CRC_1][CRC_2][CRC_3] 

Error frame: [0x02][0xFF][0x01][0x00][ERR_CODE][CRC_0][CRC_1][CRC_2][CRC_3] 

Command codes: 
	0x01 = GET_STATUS 
	0x02 = GET_PUBLIC_KEY 
	0x03 = ECDH_REQUEST 
	0x04 = GET_RANDOM 
	0xFF = ERROR 

Error codes: 
	0x01 = ERR_UNKNOWN_CMD 
	0x02 = ERR_BAD_CRC 
	0x03 = ERR_BAD_LENGTH 
	0x04 = ERR_CHIP_FAIL 