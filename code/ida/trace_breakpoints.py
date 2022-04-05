from idc import *
from idautils import *
from idaapi import *

addresses = {
    0x0620CE04: ("OpenKeyExW", "ESI", ASCSTR_UNICODE),
    0x0620CE43: ("OpenKeyExW", "ESI", ASCSTR_UNICODE),
    0x0620CE75: ("OpenKeyExW", "ESI", ASCSTR_UNICODE),
    0x0620CEF9: ("CreateKeyExW", "ESI", ASCSTR_UNICODE),
    #0x0620C665: ("EnumValue", "EDI", ASCSTR_C),
    0x0620B129: ("QueryValueExA", "EBP", ASCSTR_C),
    0x062460A9: ("QueryValueExW", "ESP", ASCSTR_UNICODE),
    0x0620B9CE: ("DeleteValueA", "ESP", ASCSTR_C),
    0x0620B64F: ("SetValueExA data", "EAX", ASCSTR_C),
    0x0620B659: ("SetValueExA name", "ESP", ASCSTR_C),
    0x06232AA1: ("InternetConnectW port", "ESP", -1),
    0x06232AA6: ("InternetConnectW server", "ESP", ASCSTR_UNICODE),
    0x06202AD4: ("CreateProcessW", "EDI", ASCSTR_UNICODE),
    0x062385B9: ("CreateProcessW", "ECX", ASCSTR_UNICODE),
    0x062369C5: ("CreateProcessW", "EDX", ASCSTR_UNICODE),
    0x06240FB0: ("CreateProcessW", "ECX", ASCSTR_UNICODE),
    0x062456E2: ("CreateProcessW commandline", "ESP", ASCSTR_UNICODE),
    0x062456E3: ("CreateProcessW application", "EBP", ASCSTR_UNICODE),
    0x062404A6: ("LoadLibraryA", "ESP", ASCSTR_C),
    0x0620E3DF: ("StartThread (Class6)", "ESP", -1),
    0x0621C192: ("StartThread (Class16)", "ESP", -1),
    0x06224E90: ("StartThread (Class21)", "ESP", -1),
    0x0624688B: ("Class6 Method", "EAX", -1),
}

def TraceHandler():
    addr = GetRegValue("EIP")
    func, reg, dType = addresses[addr]
    regValue = GetRegValue(reg)
    ptrValue = Dword(GetRegValue(reg))
    if dType == -1:
        argStr = "%d :: 0x%08X / %d :: 0x%08X" % (regValue, regValue, ptrValue, ptrValue)
    else:
        argStr = "%s :: %s" % (GetString(regValue, -1, dType),
                               GetString(ptrValue, -1, dType))
    print "0x%08X: [%s] %s" % (addr, func, argStr)

def main():
    #Lets us use python functions for breakpoint conditions
    RunPlugin("python", 3)

    for a in addresses:
        DelBpt(a)
        AddBpt(a)
        SetBptCnd(a, "TraceHandler()")
        print("Adding trace breakpoint @ %x" % a)

if __name__ == '__main__':
    main()
