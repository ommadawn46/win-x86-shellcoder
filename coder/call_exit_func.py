from coder.util import DEFAULT_HASH_KEY, push_hash


def generate(exit_func, hash_key=DEFAULT_HASH_KEY):
    if exit_func == ("KERNEL32.DLL", "TerminateProcess"):
        return f"""
        call_terminateprocess:              // BOOL TerminateProcess([in] HANDLE hProcess, [in] UINT uExitCode);
            xor   ecx, ecx                  // ECX = 0
            push  ecx                       // uExitCode = 0
            push  0xffffffff                // hProcess = 0xffffffff
            {push_hash('KERNEL32.DLL', 'TerminateProcess', hash_key)}
            call dword ptr [ebp+0x04]       // Call TerminateProcess
        """

    elif exit_func == ("ntdll.dll", "RtlExitUserThread"):
        return f"""
        call_rtlexituserthread:             // RtlExitUserThread(dwThreadExitCode);
            xor   ecx, ecx                  // ECX = 0
            push  ecx                       // dwThreadExitCode = 0
            {push_hash('ntdll.dll', 'RtlExitUserThread', hash_key)}
            call dword ptr [ebp+0x04]       // Call RtlExitUserThread
        """

    return ""
