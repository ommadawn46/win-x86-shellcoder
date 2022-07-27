DEFAULT_HASH_KEY = 0xE


def convert_ip_addr_bytes(ip_addr):
    import ipaddress

    return int(ipaddress.IPv4Address(ip_addr)).to_bytes(4, "big")


def convert_port_hex(port):
    return hex(int.from_bytes(int(port).to_bytes(2, "little"), "big"))


def convert_tag_hex(tag):
    assert len(tag) == 8 and tag[:4] == tag[4:]
    return hex(int.from_bytes(tag[:4].encode(), "little"))


def convert_neg(dword):
    return ((-int.from_bytes(dword, "little")) & 0xFFFFFFFF).to_bytes(4, "little")


def ror(byte, count):
    count %= 0x20
    return ((byte << (0x20 - count)) | (byte >> count)) & 0xFFFFFFFF


def compute_hash(module_name, function_name, key):
    hash = (len(module_name) + 1) * 2
    for c in function_name:
        hash = ror(hash, key) + ord(c)
    return hash


def push_hash(module_name, function_name, key=DEFAULT_HASH_KEY):
    hash = compute_hash(module_name, function_name, key)
    return f"push  {hex(hash)};"


def find_hash_key(functions, bad_chars):
    for key in range(0x20):
        if not any(
            any(
                c in bad_chars
                for c in compute_hash(m_name, f_name, key).to_bytes(4, "little")
            )
            for m_name, f_name in functions
        ):
            while key in bad_chars:
                key += 0x20
            return key

    print(
        f"# Cannot find a good hash key, use default key ({hex(DEFAULT_HASH_KEY)}) to compute hash"
    )
    return DEFAULT_HASH_KEY


def push_string(input_str, bad_chars, end=b"\x00"):
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

    input_bytes = input_str.encode() if type(input_str) is str else input_str
    input_bytes += end

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
