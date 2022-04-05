from idc import *
from idautils import *
from idaapi import *

def BreakpointHandler(dec_string):
    address = PrevHead(Dword(GetRegValue("ESP")), 0)
    MakeComm(address, dec_string)

def BreakpointHandlerAscii():
    dec_string = GetString(Dword(GetRegValue("EAX")), -1, ASCSTR_C)
    BreakpointHandler(dec_string)

def BreakpointHandlerUnicode():
    dec_string = GetString(Dword(GetRegValue("EAX")), -1, ASCSTR_UNICODE)
    BreakpointHandler(dec_string)

def main():
    func_ascii = 0x062022E8     #Last byte of the ascii function
    func_unicode = 0x0040F1C9   #Last byte of the unicode decrypted function

    #Lets us use python functions for breakpoint conditions
    RunPlugin("python", 3)

    AddBpt(func_ascii)
    SetBptCnd(func_ascii, "BreakpointHandlerAscii()")
    print("Breakpoint at: %x" % func_ascii)

    #AddBpt(func_unicode)
    #SetBptCnd(func_unicode, "BreakpointHandlerUnicode()")
    #print("Breakpoint at: %x" % func_unicode)

if __name__ == '__main__':
    main()
