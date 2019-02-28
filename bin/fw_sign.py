#! /usr/bin/env python3
import binascii
import hashlib
import sys

from ed25519 import SigningKey

if len(sys.argv) == 1:
    print("usage: fw_sign <firmware.bin> <privatekey.bin>")
    sys.exit(0)

# open private key and read it
with open(sys.argv[2], "rb") as privk:
    sk = SigningKey(privk.read(64))

    # read firmware binary and hash it
    with open(sys.argv[1], "rb") as fw:
        sha512 = hashlib.sha512()
        while True:
            data = fw.read(2048)
            if not data: break
            sha512.update(data)

        digest = sha512.digest()
        print("sha512   : "+bytes.decode(binascii.hexlify(digest)))

        # create signature
        signature = sk.sign(digest)
        print("signature: " + bytes.decode(binascii.hexlify(signature)))

        # write signature to file
        with open(sys.argv[1]+".sig", "w+b") as fw_s:
            fw_s.write(signature)
