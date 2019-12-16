#! /usr/bin/env python3
import binascii
import hashlib
import sys

from ed25519 import VerifyingKey

if len(sys.argv) == 1:
    print("usage: fw_verify <firmware.bin> <publickey.bin>")
    sys.exit(0)

# read verifying key
with open(sys.argv[2], "rb") as pubk:
    vk = VerifyingKey(pubk.read(64))

    # read firmware and create hash
    with open(sys.argv[1], "rb") as fw:
        sha512 = hashlib.sha512()
        while True:
            data = fw.read(2048)
            if not data: break
            sha512.update(data)

        digest = sha512.digest()
        print("sha512   : " + bytes.decode(binascii.hexlify(digest)))

        # read signature and verify
        with open(sys.argv[1] + ".sig", "rb") as fw_s:
            signature = fw_s.read(64)
            print("signature: " + bytes.decode(binascii.hexlify(signature)))
            vk.verify(signature, digest)
