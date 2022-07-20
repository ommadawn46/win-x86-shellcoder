import struct


def assemble(asm):
    from keystone import KS_ARCH_X86, KS_MODE_32, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(asm)

    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    return bytearray(sh)


def disassemble_and_find_bad_chars(shellcode, bad_chars):
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    asm = []

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions = cs.disasm(shellcode, 0)
    for ins in instructions:
        found_bad_char = False

        bytecode = ""
        for b in ins.bytes:
            if b in bad_chars:
                found_bad_char = True
            bytecode += "%02x" % b

        bad_char_mark = "[x]" if found_bad_char else "[ ]"
        padded_bytecode = bytecode + " " * (0xD - len(bytecode))
        asm.append(f"{bad_char_mark} {padded_bytecode}: {ins.mnemonic} {ins.op_str}")

    return "\n".join(asm)
