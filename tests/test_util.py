import unittest

from coder import util
from stones import assemble


class TestUtil(unittest.TestCase):
    def test_compute_hash(self):
        for args, expect in [
            (("ntdll.dll", "RtlExitUserThread"), 0xFF7F06BA),
            (("KERNEL32.DLL", "LoadLibraryA"), 0xEC0E502E),
            (("KERNEL32.DLL", "WinExec"), 0x0E8B01D8),
            (("KERNEL32.DLL", "CreateProcessA"), 0x16B46672),
            (("KERNEL32.DLL", "TerminateProcess"), 0x78CFB983),
            (("KERNEL32.DLL", "VirtualAlloc"), 0x91AFCBF4),
            (("KERNEL32.DLL", "VirtualProtect"), 0x79472E1B),
            (("KERNEL32.DLL", "WriteProcessMemory"), 0xDEBD6AA1),
            (("WS2_32.DLL", "WSAStartup"), 0xBBFCEDD0),
            (("WS2_32.DLL", "WSASocketA"), 0x2DF509DF),
            (("WS2_32.DLL", "WSAConnect"), 0x332DBA12),
            (("WS2_32.DLL", "bind"), 0xC7717AA4),
            (("WS2_32.DLL", "listen"), 0xE986ADA4),
            (("WS2_32.DLL", "accept"), 0x49DE49E5),
        ]:
            actual = util.compute_hash(
                module_name=args[0], function_name=args[1], key=0xD
            )
            self.assertEqual(actual, expect)

    def test_find_hash_key(self):
        functions = [
            ("ntdll.dll", "RtlExitUserThread"),
            ("KERNEL32.DLL", "LoadLibraryA"),
            ("KERNEL32.DLL", "WinExec"),
            ("KERNEL32.DLL", "CreateProcessA"),
            ("KERNEL32.DLL", "TerminateProcess"),
            ("KERNEL32.DLL", "VirtualAlloc"),
            ("KERNEL32.DLL", "VirtualProtect"),
            ("KERNEL32.DLL", "WriteProcessMemory"),
            ("WS2_32.DLL", "WSAStartup"),
            ("WS2_32.DLL", "WSASocketA"),
            ("WS2_32.DLL", "WSAConnect"),
            ("WS2_32.DLL", "bind"),
            ("WS2_32.DLL", "listen"),
            ("WS2_32.DLL", "accept"),
        ]

        for bad_chars, expect_key, expect_contains_bad_chars in [
            (b"", 0x0, False),
            (b"\x00", 0x5, False),
            (b"\x00\x2F", 0x8, False),
            (b"\x00\x2F\x3D", 0xA, False),
            (b"\x00\x0D\x2F\x3D", 0xD, False),
            (b"\x00\x0D\x2E\x2F\x3D", 0xE, False),
            (b"\x00\x0D\x2D\x2E\x2F\x3D", 0x12, False),
            (b"\x00\x0D\x2D\x2E\x2F\x3D\x3F", 0x14, False),
            (b"\x00\x0A\x0D\x2D\x2E\x2F\x3D\x3F", 0x19, False),
            (b"\x00\x0A\x0D\x2D\x2E\x2F\x3C\x3D\x3F", util.DEFAULT_HASH_KEY, True),
        ]:
            actual_key = util.find_hash_key(functions=functions, bad_chars=bad_chars)
            self.assertEqual(actual_key, expect_key)

            actual_contains_bad_chars = any(
                any(
                    c in bad_chars
                    for c in util.compute_hash(
                        module_name=m_name, function_name=f_name, key=actual_key
                    ).to_bytes(4, "little")
                )
                for m_name, f_name in functions
            )
            self.assertEqual(actual_contains_bad_chars, expect_contains_bad_chars)

    def test_push_string(self):
        push_chars = [0x35, 0x50, 0xB8, 0xD8, 0xF7]

        for args, expect in [
            (("foo", b""), "push  0x6f6f66;"),
            (("foo", b"\x00\x66\x6F"), "mov   eax, 0xff90909a;neg   eax;push  eax;"),
            (
                ("foo", b"\x00\x66\x6F\xFF"),
                "mov   eax, 0x1010101;xor   eax, 0x16e6e67;push  eax;",
            ),
            (("foobarbaz", b""), "push  0x7a;push  0x61627261;push  0x626f6f66;"),
            (
                ("foobarbaz", b"\x00\x61\x62\x66\x6F\x72\x7A"),
                "mov   eax, 0xfefeff86;neg   eax;push  eax;mov   eax, 0x9e9d8d9f;neg   eax;push  eax;mov   eax, 0x9d90909a;neg   eax;push  eax;",
            ),
            (
                ("foobarbaz", b"\x00\x61\x62\x66\x6F\x72\x7A\xFF"),
                "mov   eax, 0x2020101;xor   eax, 0x303017b;push  eax;mov   eax, 0x9e9d8d9f;neg   eax;push  eax;mov   eax, 0x9d90909a;neg   eax;push  eax;",
            ),
            (
                ("foobarbaz", b"\x00\x61\x62\x66\x6F\x72\x7A\x8D\xFF"),
                "mov   eax, 0x2020101;xor   eax, 0x303017b;push  eax;mov   eax, 0x1010101;xor   eax, 0x60637360;push  eax;mov   eax, 0x9d90909a;neg   eax;push  eax;",
            ),
            (
                ("foobarbaz", b"\x00\x61\x62\x66\x6F\x72\x7A\x8D\x90\xFF"),
                "mov   eax, 0x2020101;xor   eax, 0x303017b;push  eax;mov   eax, 0x1010101;xor   eax, 0x60637360;push  eax;mov   eax, 0x1010101;xor   eax, 0x636e6e67;push  eax;",
            ),
            (
                (
                    "foobarbaz",
                    bytes([c for c in range(0x7F) if c not in push_chars])
                    + b"\x8D\x90\xFF",
                ),
                "mov   eax, 0x80803580;xor   eax, 0xb5b535fa;push  eax;mov   eax, 0x80808080;xor   eax, 0xe1e2f2e1;push  eax;mov   eax, 0x80808080;xor   eax, 0xe2efefe6;push  eax;",
            ),
            (
                (
                    "foobarbaz",
                    b"\x00"
                    + bytes([c for c in range(0x41, 0x100) if c not in push_chars]),
                ),
                "mov   eax, 0x202012a;xor   eax, 0x3030150;push  eax;mov   eax, 0x21222221;xor   eax, 0x40405040;push  eax;mov   eax, 0x222f2f26;xor   eax, 0x40404040;push  eax;",
            ),
        ]:
            actual = util.push_string(input_str=args[0], bad_chars=args[1])
            self.assertEqual(actual, expect)

            shellcode = assemble(asm=actual)
            self.assertFalse(any(c in args[1] for c in shellcode))
