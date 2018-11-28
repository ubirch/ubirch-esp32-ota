#! /usr/bin/env python3
import binascii
import sys
import hashlib

from ed25519 import SigningKey

if len(sys.argv) == 1:
    print("usage: fw_sign <firmware.bin> <privatekey.bin>")
    sys.exit(0)

with open(sys.argv[2], "rb") as privk:
    sk = SigningKey(privk.read(64))
    with open(sys.argv[1], "rb") as fw:
        sha512 = hashlib.sha512()
        while True:
            data = fw.read(2048)
            if not data: break
            sha512.update(data)

        digest = sha512.digest()
        print("sha512   : "+bytes.decode(binascii.hexlify(digest)))
        signed_firmware = sk.sign(sha512.digest())
        print("signature: "+bytes.decode(binascii.hexlify(signed_firmware)))
        with open(sys.argv[1]+".sig", "w+b") as fw_s:
            fw_s.write(signed_firmware)