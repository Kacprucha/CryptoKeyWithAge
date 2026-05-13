import hashlib, binascii

OID = bytes([0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07]) # nistp256
shared_secret = bytes(range(32)) # 00..1F
fingerprint = bytes(range(20)) # 00..13

data = (
    b'\x00\x00\x00\x01' +            # counter
    shared_secret +
    bytes([0x13]) +                  # param_len
    bytes([len(OID)]) + OID +
    bytes([0x08, 0x09]) +            # SHA-256, AES-256
    b'Anonymous Sender    ' +        # 20B ze spacjami
    fingerprint
)

print(hashlib.sha256(data).hexdigest().upper())