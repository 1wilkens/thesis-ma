from __future__ import print_function

from idc import *
from idautils import *
from idaapi import *

fixed_addr = 0x062180F0

def FixBrokenCPUHandler():
    #print("Fixing CPU..")

    esp_cur = GetRegValue("ESP")
    esp_new = esp_cur - 4
    #print("Current ESP=0x%X, new ESP=0x%X" % (esp_cur, esp_new))

    eip_cur = GetRegValue("EIP")
    eip_new = NextHead(eip_cur);
    #print("Current EIP=0x%X, new EIP=0x%X" % (eip_cur, eip_new))

    # increment esp
    SetRegValue(esp_new, "ESP")

    # write eip eip
    PatchDbgByte(esp_new + 0, eip_new & 0x000000FF)
    PatchDbgByte(esp_new + 1, (eip_new & 0x0000FF00) >> 8)
    PatchDbgByte(esp_new + 2, (eip_new & 0x00FF0000) >> 16)
    PatchDbgByte(esp_new + 3, (eip_new & 0xFF000000) >> 24)

    #print("Setting new EIP!")
    SetRegValue(fixed_addr, "EIP")

    #print("Done!")

def main():
    broken_call = 0x06201F11
    #broken_call = 0x6243BC5 # for testing

    #Lets us use python functions for breakpoint conditions
    RunPlugin("python", 3)

    AddBpt(broken_call)
    SetBptCnd(broken_call, "FixBrokenCPUHandler()")
    print("Fixing broken call at: 0x%X" % broken_call)

if __name__ == '__main__':
    main()
