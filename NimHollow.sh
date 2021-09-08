#!/usr/bin/env bash

cd NimlineWhispers

cat << 'EOT' > functions.txt
NtQueryInformationProcess
NtReadVirtualMemory
NtProtectVirtualMemory
NtWriteVirtualMemory
NtResumeThread
NtClose
EOT

python3 NimlineWhispers.py --randomise

cat << 'EOT' >> syscalls.nim
type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST
EOT

mv syscalls.nim ../syscalls.nim
