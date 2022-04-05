from idautils import *
from idc import *
from idaapi import *

dlls = {
    0xCD721670: "advapi32.dll",
    0x8208B18D: "kernel32.dll",
    0xFB26EC20: "ntdll.dll",
    0x29F79643: "psapi.dll",
    0xA22A99B3: "shell32.dll",
    0xA9FD28DF: "shlwapi.dll",
    0xA7E1A6D3: "user32.dll",
    0x03076155: "wininet.dll",
    0x40B523A1: "wtsapi32.dll"
}

fns = {
    0x960BD6BA: "advapi32.CryptAcquireContextW",
    0x62DD7780: "advapi32.CryptReleaseContext",
    0x1D116AF1: "advapi32.CryptGenRandom",
    0x15A4E5A2: "advapi32.CryptCreateHash",
    0xC0F98CAE: "advapi32.CryptDestroyHash",
    0x0C7ECC5E: "advapi32.CryptHashData",
    0xCC8BDFA1: "advapi32.CryptGetHashParam",
    0x673FE28C: "advapi32.GetUserNameW",
    0xF3920AEF: "advapi32.RegEnumKeyA",
    0x6A9C9B87: "advapi32.RegCreateKeyExW",
    0xFF7382CC: "advapi32.RegOpenKeyExW",
    0x63B44C7B: "advapi32.RegCloseKey",
    0x7AA4E0B0: "advapi32.RegQueryValueExA",
    0x8E7055E1: "advapi32.RegQueryValueExW",
    0x8590E6D7: "advapi32.RegSetValueExA",
    0x31EF0012: "advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW",
    0x305AE280: "advapi32.GetSecurityDescriptorSacl",
    0xC4CEAF1C: "advapi32.SetSecurityInfo",
    0x0DAE3598: "advapi32.AllocateAndInitializeSid",
    0xFBF064F3: "advapi32.FreeSid",
    0x9A8AEA43: "advapi32.EqualSid",
    0xBC089C82: "advapi32.GetSidSubAuthorityCount",
    0x369FAC00: "advapi32.GetSidSubAuthority",
    0x335B4B5B: "advapi32.OpenProcessToken",
    0xDCC8E5F3: "advapi32.GetTokenInformation",
    0xF55CF0C3: "kernel32.LoadLibraryA",
    0x01884592: "kernel32.LoadLibraryW",
    0x10F56EC1: "kernel32.FreeLibrary",
    0x7A0E58BA: "kernel32.CloseHandle",
    0x96182109: "kernel32.CreateProcessW",
    0x2C3A9212: "kernel32.CreateProcessAsUserW",
    0x15BA1C05: "kernel32.OpenProcess",
    0xEF8DDA82: "kernel32.ExitProcess",
    0x61DDF2C3: "kernel32.TerminateProcess",
    0xD6571EB3: "kernel32.GetExitCodeProcess",
    0xE4CD7945: "kernel32.IsWow64Process",
    0x4B0A4D02: "kernel32.Process32FirstW",
    0x76F62AF1: "kernel32.Process32FirstW",
    0x1A1B57EA: "kernel32.GetCurrentProcess",
    0xD7295EAD: "kernel32.GetCurrentProcessId",
    0x51A02CEE: "kernel32.GetProcessId",
    0x8A6B0F23: "kernel32.GetProcessHeap",
    0x33B9B3A9: "kernel32.GetProcessTimes",
    0x046FA0E6: "kernel32.Sleep",
    0x18787BF9: "kernel32.GetLastError",
    0x1766AD7A: "kernel32.SetLastError",
    0x5AF74BFE: "kernel32.CreateThread",
    0xAD28820E: "kernel32.FreeLibraryAndExitThread",
    0x72C9CBB1: "kernel32.OpenThread",
    0x1DC5A4FD: "kernel32.GetThreadId",
    0x4765332D: "kernel32.GetCurrentThreadId",
    0xE9167C5A: "kernel32.Thread32First",
    0x3F843A49: "kernel32.Thread32Next",
    0x1331691D: "kernel32.CreateMutexA",
    0x3B0FE952: "kernel32.OpenMutexA",
    0xED72CB91: "kernel32.ReleaseMutex",
    0x6B72A467: "kernel32.CreateFileW",
    0xAFD293D4: "kernel32.DeleteFileW",
    0xBF044EB2: "kernel32.CreateDirectoryW",
    0x0DACFDF1: "kernel32.RemoveDirectoryW",
    0xE66E7D1A: "kernel32.GetShortPathNameW",
    0x7E86DF22: "kernel32.CreateFileMappingA",
    0x12B6BBD4: "kernel32.FindClose",
    0xF7A22DD1: "kernel32.FindFirstFileW",
    0x4B6ED157: "kernel32.FindNextFileW",
    0x0E29E403: "kernel32.GetFileAttributesW",
    0x2B226F1D: "kernel32.SetFileAttributesW",
    0x6D660C2B: "kernel32.GetFileSize",
    0xC3C14E9E: "kernel32.ReadFile",
    0x06741B5C: "kernel32.WriteFile",
    0x255AA73A: "kernel32.SetFilePointer",
    0x42256301: "kernel32.GetEnvironmentStrings",
    0x6C27F5D2: "kernel32.GetExpandEnvironmentStringsA",
    0x98F34083: "kernel32.GetExpandEnvironmentStringsW",
    0x0B6EF538: "kernel32.CreateToolhelp32Snapshot",
    0x132F49DA: "kernel32.GetCommandLineW",
    0x701E89B8: "kernel32.GetComputerNameA",
    0x84CA3CE9: "kernel32.GetComputerNameW",
    0x36F60FBF: "kernel32.GetModuleFileNameW",
    0xB8F95145: "kernel32.GetSystemDirectoryW",
    0xE1CE8E55: "kernel32.GetVersionExW",
    0x1FB00A04: "kernel32.GetVolumeInformationW",
    0xB86C5377: "kernel32.MultiByteToWideChar",
    0x501DA8C7: "kernel32.WideCharToMultiByte",
    0x18BF49AA: "kernel32.GetSystemTime",
    0xF268DDF5: "kernel32.SystemTimeToFileTime",
    0x47EAFDF5: "kernel32.GlobalGetAtomNameA",
    0xB33E48A4: "kernel32.GlobalGetAtomNameW",
    0x93A53738: "kernel32.GlobalAddAtomW",
    0x108D03F5: "kernel32.GlobalDeleteAtom",
    0xF08701B7: "kernel32.CreateEventA",
    0xD8B981F8: "kernel32.OpenEventA",
    0x01669829: "kernel32.SetEvent",
    0xD5ADDFFE: "kernel32.ResetEvent",
    0x2AC5F60B: "kernel32.WaitForSingleObject",
    0x7312198A: "kernel32.WaitForMultipleObjects",
    0x03E152B1: "kernel32.GetProcAddress",
    0x9B350405: "kernel32.IsBadReadPtr",
    0x8F0A7A60: "kernel32.IsBadWritePtr",
    0xC3534004: "kernel32.VirtualAlloc",
    0x07CEB893: "kernel32.VirtualFree",
    0xDA9B2261: "kernel32.VirtualProtect",
    0xF495BAC5: "kernel32.LocalFree",
    0x7A6BA5E7: "kernel32.HeapFree",
    0x32916CD5: "ntdll.RtlCreateHeap",
    0x6B49143A: "ntdll.RtlAllocateHeap",
    0x9214E5B0: "ntdll.RtlReAllocateHeap",
    0x658CF16A: "ntdll.RtlFreeHeap",
    0x7CD15EA0: "ntdll.LdrGetProcedureAddress",
    0xD2AB34BC: "ntdll.LdrLoadDll",
    0x28815108: "ntdll.LdrGetDllHandle",
    0x0ADF59DD: "ntdll.RtlQueryElevationFlags",
    0x6F59011E: "ntdll.NtQueryInformationProcess",
    0xC96BBEC2: "ntdll.NtQueryVirtualMemory",
    0x2AEB62A5: "ntdll.NtAllocateVirtualMemory",
    0x96B057D9: "ntdll.NtProtectVirtualMemory",
    0x4BBF7F5C: "ntdll.NtReadVirtualMemory",
    0x2E1AD477: "ntdll.NtWriteVirtualMemory",
    0x6E8B73F2: "ntdll.NtMapViewOfSection",
    0x5AD572B8: "ntdll.NtUnmapViewOfSection",
    0x18A6314C: "ntdll.NtDuplicateObject",
    0x17C80BCF: "ntdll.NtWaitForSingleObject",
    0xAAF28AFC: "ntdll.NtSetEvent",
    0xA8EEF83C: "ntdll.NtResumeThread",
    0x984F576F: "ntdll.RtlCreateUserThread",
    0x4A322FAF: "ntdll.RtlExitUserThread",
    0xC7948A1E: "ntdll.NtClose",
    0xE9C64EDE: "ntdll.NtQueueApcThread",
    0x3F352F36: "ntdll.NtDelayExecution",
    0x9D6C3625: "ntdll.memcmp",
    0x1BDCE29D: "ntdll.memcpy",
    0x4A717A64: "ntdll.memmove",
    0x4EFEDB44: "ntdll.memset",
    0x78327B3B: "ntdll.vsnprintf",
    0xF75E1BF1: "ntdll.vsnwprintf",
    0x7AE3BF4D: "psapi.EnumProcessModulesEx",
    0x2969A921: "psapi.GetModuleBaseNameW",
    0x38350B78: "psapi.GetModuleInformation",
    0x48BAC947: "psapi.GetProcessImageFileNameW",
    0xBE27A211: "shell32.CommandLineToArgvW",
    0x0DF86671: "shell32.SHGetFolderPathW",
    0x7724ED86: "shell32.ShellExecuteExW",
    0x75079C54: "shlwapi.SHDeleteKeyA",
    0x453F7455: "user32.GetThreadDesktop",
    0xF9B98716: "user32.GetWindowTextW",
    0x3273CDA2: "user32.GetWindowThreadProcessId",
    0xB1630831: "user32.GetClassNameW",
    0x89C72D45: "user32.EnumWindows",
    0x6DCEA281: "user32.SetForegroundWindow",
    0xDFE5741B: "user32.SwitchToThisWindow",
    0x3CFCC5B9: "wininet.HttpQueryInfoW",
    0x7A34F074: "wininet.HttpOpenRequestW",
    0xC14949E9: "wininet.HttpSendRequestW",
    0x2F84506A: "wininet.InternetCloseHandle",
    0xFC065DEB: "wininet.InternetConnectW",
    0xA65DD5BB: "wininet.InternetReadFile",
    0xFB066D47: "wininet.InternetQueryOptionW",
    0x741344F1: "wininet.InternetSetOptionW",
    0x108BE573: "wininet.InternetOpenA",
    0x93C87DA3: "wtsapi32.WTSEnumerateSessionsW",
    0x3F46213A: "wtsapi32.WTSFreeMemory",
    0x36EDA97D: "wtsapi32.WTSQueryUserToken"
}

imms = set()

start = 0x1001000
end   = 0x1015000

print "From 0x%X to 0x%X" % (start, end)

c_dll = c_fn = c_u = 0

for f in Functions(start, end):
    name = GetFunctionName(f)
    for (s, e) in Chunks(f):
        for addr in Heads(s, e):
            # Check only 'mov's
            if GetMnem(addr) == "mov":
                insn = idaapi.decode_insn(addr)
                op = idaapi.cmd.Operands[1]
                # Check only immediates as second operand
                if op.type == idaapi.o_imm:
                    val = op.value & 0xFFFFFFFF # Truncate 64 bit values as they are not used anyway
                    # Check whether its a dll hash
                    if val in dlls:
                        dll = dlls[val]
                        #print "Dll hash @ 0x%X: 0x%X == %s" % (addr, val, dll)
                        MakeComm(addr, dll)
                        c_dll += 1
                    # Check whether its a fn hash
                    elif val in fns:
                        fn = fns[val]
                        #print "Fn hash @ 0x%X: 0x%X == %s" % (addr, val, fn)
                        MakeComm(addr, fn)
                        c_fn += 1
                    elif val >= 0x00FFFFFF and val != 0x7FFFFFFF and hex(val)[-8:-1] != "0000000" and val not in imms:
                        imms.add(val)
                        print "Unknown immediate @ 0x%X: 0x%X" % (addr, val)
                        c_u += 1

print "done!"
print "Found %d dlls, %d functions and %d unknown immediates" % (c_dll, c_fn, c_u)
