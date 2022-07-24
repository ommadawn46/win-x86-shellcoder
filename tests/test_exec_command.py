import random
import socket
import time
import unittest

from coder import exec_command
from runner import load_shellcode, run_shellcode
from stones import assemble


class TestExecCommand(unittest.TestCase):
    def test_run_shellcode(self):
        port = random.randint(49152, 65535)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("0.0.0.0", port))
            s.listen()

            code = exec_command.generate(
                cmd=f"powershell -c curl http://127.0.0.1:{port}/pwned | Out-Null",
                bad_chars=b"\x00",
                exit_func=("ntdll.dll", "RtlExitUserThread"),
                debug=False,
            )
            shellcode = assemble(code)

            ptr = load_shellcode(shellcode)
            run_shellcode(ptr, wait=True)
            time.sleep(1)

            client_s, _ = s.accept()

        resp = client_s.recv(0x1000)
        client_s.send(b"HTTP/1.1 200 OK\r\n\r\n")
        client_s.close()

        self.assertIn(b"GET /pwned HTTP/1.1", resp)
