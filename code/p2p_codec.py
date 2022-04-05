#!/usr/bin/env python3

import struct
import gzip
import random
import sys

from p2p_utils import cryptRC4, formatBytes, intOverflow, MINSIZE, MAXSIZE

def generateChecksumHeader():
    header = []
    s = 0

    for i in range(31):
        rnd = random.randint(MINSIZE, MAXSIZE)
        s = intOverflow(s + rnd)
        header.append(rnd.to_bytes(4, sys.byteorder, signed=True))
    header.append(intOverflow(-s).to_bytes(4, sys.byteorder, signed=True))
    return b"".join(header)


def encryptPayloadLength(payloadLength):
    hpart = payloadLength // 30000
    lpart = payloadLength % 30000
    if hpart:
        hpartbytes = struct.pack('<h', -hpart)
    else:
        hpartbytes = b"\x00\x00"
    if lpart:
        lpartbytes = struct.pack('<h', -lpart)
    else:
        lpartbytes = b"\x00\x00"
    return hpartbytes + lpartbytes


def decryptPayloadLength(payloadLength):
    # TODO implement
    pass


def encryptP2PMessage(msg):
    print("[ENC] Encrypting:", formatBytes(msg), file=sys.stderr)

    # Compress message with gzip
    msgGz = list(gzip.compress(msg))
    msgGz[4:8] = [0] * 4   # Zero out time
    msgGz = bytes(msgGz)
    msgLengthGz = len(msgGz)
    print("[ENC] Gzipped length:", msgLengthGz, file=sys.stderr)

    # Generate 2 16-Byte RC4 keys
    rc4Length = bytes(random.randint(0, 255) for _ in range(16))
    rc4Msg = bytes(random.randint(0, 255) for _ in range(16))

    # Encrypt len and message with RC4
    msgLengthGzEnc = cryptRC4(msgLengthGz.to_bytes(4, 'big', signed=True), rc4Length)
    msgGzEnc = cryptRC4(msgGz, rc4Msg)

    # Calculate total length
    payloadLength = 16 + 4 + 16 + msgLengthGz
    print("[ENC] Payload length:", payloadLength, file=sys.stderr)
    payloadLengthConv = encryptPayloadLength(payloadLength)

    # Assemble packet
    packet = generateChecksumHeader() \
        + payloadLengthConv \
        + rc4Length \
        + msgLengthGzEnc \
        + rc4Msg \
        + msgGzEnc

    # Print packet to stdout
    print("[ENC] Done!", file=sys.stderr)
    return packet


def decryptP2PMessage(crypt):
    if len(crypt) < 168:
        return None

    crypt = crypt[128:]
    print("[DEC] Decrypting: ", formatBytes(crypt), file=sys.stderr)

    payloadLength = decryptPayloadLength(crypt[:4])

    rc4Length = crypt[4:20]
    msgLengthGz = cryptRC4(crypt[20:24], rc4Length)
    print("[DEC] Payload length:", msgLengthGz, file=sys.stderr)

    rc4Msg = crypt[24:40]
    msgGz = cryptRC4(crypt[40:], rc4Msg)
    print("[DEC] Gzipped length:", len(msgGz), file=sys.stderr)
    if len(msgGz) == 0:
        return None
    try:
        msg = gzip.decompress(msgGz)
    except OSError:
        return None
    print("[DEC] Decrypted:", formatBytes(msg), file=sys.stderr)

    print("[DEC] Done!", file=sys.stderr)
    return msg


def main():
    mode = sys.argv[1]

    if mode == "-e":
        msg = sys.stdin.buffer.read()
        enc = encryptP2PMessage(msg)
        sys.stdout.buffer.write(enc)
    elif mode == "-d":
        crypt = sys.stdin.buffer.read()
        dec = decryptP2PMessage(crypt)
        if dec is not None:
            sys.stdout.buffer.write(dec)
    else:
        raise Exception("Use e to encrypt or d to decrypt")


if __name__ == "__main__":
    main()
