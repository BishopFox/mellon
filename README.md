## OSDP Vulnerabilities this Exploits
OSDP attack tool (and the Elvish word for friend)

### Attack #1: Encryption is Optional

OSDP supports, but doesn't strictly *require*, encryption. So your connection might not even be encrypted at all. Attack #1 is just to passively listen and see if you can read the card numbers on the wire.

### Attack #2: Downgrade Attack

Just because the controller and reader *support* encryption doesn't mean they're configured to *require* it be used. An attacker can modify the reader's capability reply message (osdp_PDCAP) to advertise that it doesn't support encryption. When this happens, some controllers will barrel ahead without encryption.

### Attack #3: Install-mode Attack

OSDP has a quasi-official “install mode” that applies to both readers and controllers. As the name suggests, it’s supposed to be used when first setting up a reader. What it does is essentially allow readers to ask the controller for what the base encryption key (the SCBK) is. If the controller is configured to be persistently in install-mode, then an attacker can show up on the wire and request the SCBK. 

### Attack #4: Weak Keys

OSDP sample code often comes with hardcoded encryption keys. Clearly these are meant to be samples, where the user is supposed to generate keys in a secure way on their own. But this is not explained or made simple for the user, however. And anyone who’s been in security long enough knows that whatever’s the default is likely to be there in production. 

So as an attack vector, when the link between reader and controller is encrypted, it’s worth a shot to enumerate some common weak keys. Now these are 128-bit AES keys, so we’re not going to be able to enumerate them all. Or even a meaningful portion of them. But what we can do is hit some common patterns that you see when someone hardcodes a key: 

- All single-byte values. [0x04, 0x04, 0x04, 0x04 …]
- All monotonically increasing byte values. [0x01, 0x02, 0x03, 0x04, …]
- All monotonically decreasing byte values. [0x0A, 0x09, 0x08, 0x07, …]

### Attack #5: Keyset Capture

OSDP has no in-band mechansim for key exchange. What this means is that an attacker can:

- Insert a covert listening device onto the wire. 
- Break / factory reset / disable the reader.
- Wait for someone from IT to come and replace the reader.
- Capture the keyset message (osdp_KEYSET) when the reader is first setup.
- Decrypt all future messages.

## Getting A Testbed Setup (Linux/MacOS)

You'll find proof-of-concept code for each of these attacks in `attack_osdp.py`. Checkout the `--help` command for more details on usage. This is a Python script, meant to be run from a laptop with USB<-->RS485 adapters [like one of these](https://www.amazon.com/Serial-Converter-Adapter-Supports-Windows/dp/B0195ZD3P4/). So you'll probably want to pick some of those up. Doesn't have to be that model, though.

If you have a controller you want to test, then great. Use that. If you don't, then we have an intentionally-vulnerable OSDP controller that you can use here: `vulnserver.py`. 

Some of the attacks in `attack_osdp.py` will expect to be as a full MitM between a functioning reader and controller. To test these, you might need *three* USB<-->RS485 adapters, hooked together with a breadboard.

### Additional Medium / Low Risk Issues

These issues are not, in isolation, exploitable but nonetheless represent a weakening of the protocol, implementation, or overall system.

- MACs are truncated to 32 bits "to reduce overhead". This is _very_ nearly (but not quite in our calculation) within practical exploitable range.
- IVs (which are derived from MACs) are similarly reduced to 32 bits of entropy. This will cause IV reuse, which is a big red flag for a protocol.
- Session keys are only generated using 48 bits of entropy from the controller RNG nonce. This appears to not be possible for an observing attacker to enumerate offline, however. (Unless we're missing something, in which case this would become a _critical_ issue.)
- Sequence numbers consist of only 2 bits, not providing sufficient liveness.
- CBC-mode encryption is used. GCM would be a more modern block cipher mode appropriate for network protocols.
- SCS modes 15 & 16 are essentially "null ciphers", and should not exist. They don't encrypt data.
- The OSDP command byte is always unencrypted, even in the middle of a Secure Channel session. This is a huge benefit to attackers, making attack tools much easier to write. It means that an attacker can always see what "type" of packet is being sent, even if it's otherwise encrypted. Attackers can tell when people badge in, when the LED lights up, etc... This is not information that should be in plaintext.
- SCBK-D (a hardcoded "default" encryption key) provides no security and should be removed. It serves only to obfuscate and provide a false sense of security. 
