import unittest

import stones


class TestReplaceInstructions(unittest.TestCase):
    def test_replace_instructions(self):
        for args, expect in [
            (
                ("mov dword ptr [eax + 0x20], ebx", b""),
                "mov dword ptr [eax + 0x20], ebx",
            ),
            (
                ("mov dword ptr [ebx + 0x20], ecx", b"\x20"),
                "dec ebx;mov dword ptr [ebx+0x21], ecx;inc ebx",
            ),
            (
                ("mov dword ptr [ecx + 0x20], edx", b"\x20\x21"),
                "inc ecx;mov dword ptr [ecx+0x1f], edx;dec ecx",
            ),
            (
                ("mov dword ptr [edx + 0x20], esi", b"\x1F\x20\x21"),
                "dec edx;dec edx;mov dword ptr [edx+0x22], esi;inc edx;inc edx",
            ),
            (
                ("mov dword ptr [esi + 0x20], edi", bytes(c for c in range(0x0, 0x42))),
                "inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;mov dword ptr [esi-0x1], edi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi",
            ),
            (
                ("mov ebx, dword ptr [eax + 0x20]", b""),
                "mov ebx, dword ptr [eax + 0x20]",
            ),
            (
                ("mov ecx, dword ptr [ebx + 0x20]", b"\x20"),
                "dec ebx;mov ecx, dword ptr [ebx+0x21];inc ebx",
            ),
            (
                ("mov edx, dword ptr [ecx + 0x20]", b"\x20\x21"),
                "inc ecx;mov edx, dword ptr [ecx+0x1f];dec ecx",
            ),
            (
                ("mov esi, dword ptr [edx + 0x20]", b"\x1F\x20\x21"),
                "dec edx;dec edx;mov esi, dword ptr [edx+0x22];inc edx;inc edx",
            ),
            (
                ("mov edi, dword ptr [esi + 0x20]", bytes(c for c in range(0x0, 0x42))),
                "inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;inc esi;mov edi, dword ptr [esi-0x1];dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi;dec esi",
            ),
        ]:
            actual = stones.replace_instructions(args[0], args[1])
            joined_actual = ";".join(actual.strip().split("\n"))
            self.assertEqual(joined_actual, expect)
