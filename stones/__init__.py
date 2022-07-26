import re

from stones.replace_instruction import replace_insn


def assemble(asm):
    from keystone import KS_ARCH_X86, KS_MODE_32, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(asm)
    if encoding:
        return bytearray(encoding)


def disassemble(shellcode):
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    return cs.disasm(shellcode, 0)


def find_bad_chars(instructions, bad_chars):
    asm = []
    for insn in instructions:
        found_bad_char = False
        bytecode = ""
        for b in insn.bytes:
            if b in bad_chars:
                found_bad_char = True
            bytecode += "%02x" % b
        asm.append((found_bad_char, bytecode, insn.mnemonic, insn.op_str))
    pad_length = max(map(lambda x: len(x[1]), asm)) + 1

    result = []
    for found_bad_char, bytecode, mnemonic, op_str in asm:
        bad_char_mark = "[x]" if found_bad_char else "[ ]"
        padded_bytecode = bytecode + " " * (pad_length - len(bytecode))
        result.append(f"{bad_char_mark} {padded_bytecode}: {mnemonic} {op_str}")
    return "\n".join(result)


def replace_instructions(code, bad_chars):
    new_code = []

    code = "\n".join(map(lambda x: x.split("//")[0], code.split("\n")))
    for insn_str in re.split(r"[\n\r;]", code):
        new_insn_str = replace_insn(insn_str, bad_chars)
        new_code.append(new_insn_str if new_insn_str else insn_str)

    return "\n".join(new_code)
