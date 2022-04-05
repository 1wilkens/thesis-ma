#!/usr/bin/python

import os

files = [f for f in os.listdir('.') if os.path.isfile(f) and os.path.splitext(f)[1] == ".hex"]
for f in files:
    with open(f, "r") as s:
        raw = s.read().replace("\n", "")
        decoded = raw.decode("hex")
        with open(os.path.splitext(f)[0] + ".bin", "wb") as o:
            o.write(decoded)
