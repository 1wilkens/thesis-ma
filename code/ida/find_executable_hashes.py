from os import walk
from zlib import crc32

inject_hashes = {
    0xC3DDC6D5,
    0x9C1D0D0E,
    0xB4E35F10,
    0x2CB1CAD3,
}

terminate_hashes = {
    0x4420EF23,
    0x29D7F43D,
    0x218453BA,
    0x544C4832,
    0xBE9263FB,
    0xC067569F,
    0x87B1CD48,
    0x9D8FDA87,
    0x4202BE94,
    0xA76792D3,
    0x0D3F42A1,
    0xA530203A,
    0x5BDAC48B,
    0xF3BE1777,
    0x2E03DA46,
    0xA79FBF07,
    0xF4BC0570,
}

def main():
    for _, __, files in walk(r"C:\\"):
        for fname in files:
            crc = crc32(fname) & 0xFFFFFFFF
            if crc in inject_hashes:
                print "[ATTK] 0x%X: %s" % (crc, fname)
            if crc in terminate_hashes:
                print "[KILL] 0x%X: %s" % (crc, fname)

if __name__ == "__main__":
    main()
