def assemble(asm):
    from keystone import KS_ARCH_X86, KS_MODE_32, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(asm)
    return bytearray(encoding)


def disassemble(shellcode):
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    return cs.disasm(shellcode, 0)


def find_bad_chars(instructions, bad_chars):
    asm = []
    for ins in instructions:
        found_bad_char = False
        bytecode = ""
        for b in ins.bytes:
            if b in bad_chars:
                found_bad_char = True
            bytecode += "%02x" % b
        asm.append((found_bad_char, bytecode, ins.mnemonic, ins.op_str))
    pad_length = max(map(lambda x: len(x[1]), asm)) + 1

    result = []
    for found_bad_char, bytecode, mnemonic, op_str in asm:
        bad_char_mark = "[x]" if found_bad_char else "[ ]"
        padded_bytecode = bytecode + " " * (pad_length - len(bytecode))
        result.append(f"{bad_char_mark} {padded_bytecode}: {mnemonic} {op_str}")
    return "\n".join(result)
