MINSIZE = -2147483648
MAXSIZE = 2147483647

# From https://stackoverflow.com/a/14246007
def intOverflow(value):
    base = 1 << 32
    value %= base
    return value - base if value.bit_length() == 32 else value

def formatBytes(inp):
    return ' '.join('{:02X}'.format(x) for x in inp)

# From https://github.com/bozhu/RC4-Python
def KSA(key):
    keylength = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

# Convenience function for applying RC4
def cryptRC4(buffer, key):
    return bytes(map(lambda x: x[0]^x[1], zip(buffer, RC4(key))))
