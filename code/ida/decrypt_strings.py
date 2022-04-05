from idc import *
from idautils import *
from idaapi import *

counter = 1

def PrintDecryptedString():
    global counter
    dec_string = GetString(Dword(GetRegValue("EAX")), -1, ASCSTR_C)
    if dec_string is None or dec_string == "":
        print "Found null string.. Exiting.."
        PauseProcess()
    else:
        print "Decrypted [%d]: %s" % (counter - 1, dec_string)
        SetRegValue(0x004029B2, "EIP")
        SetRegValue(counter, "EDX")
        counter += 1

def main():
    func = 0x004029BA   #Last byte of the unicode decrypted function

    #Lets us use python functions for breakpoint conditions
    RunPlugin("python", 3)

    AddBpt(func)
    SetBptCnd(func, "PrintDecryptedString()")

if __name__ == '__main__':
    main()
