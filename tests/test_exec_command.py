import random
import socket
import time
import unittest

import stones
from coder import exec_command
from runner import load_shellcode, run_shellcode


def test_exec_command_shellcode(shellcode, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen()

        ptr = load_shellcode(shellcode)
        run_shellcode(ptr, wait=True)
        time.sleep(1)

        client_s, _ = s.accept()

    resp = client_s.recv(0x1000)
    client_s.send(b"HTTP/1.1 200 OK\r\n\r\n")
    client_s.close()

    return b"GET /pwned HTTP/1.1" in resp


class TestExecCommand(unittest.TestCase):
    def test_run_shellcode(self):
        port = random.randint(49152, 65535)
        bad_chars = b"\x00"

        code = exec_command.generate(
            cmd=f"powershell -c curl http://127.0.0.1:{port}/pwned | Out-Null",
            bad_chars=bad_chars,
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        shellcode = stones.assemble(code)
        self.assertFalse(any(c in bad_chars for c in shellcode))

        self.assertTrue(test_exec_command_shellcode(shellcode, port))

    def test_run_replaced_shellcode(self):
        port = random.randint(49152, 65535)
        bad_chars = b"\x00\x08\x09\x18\x19\x1C\x1F\x20\x30"

        code = exec_command.generate(
            cmd=f"powershell -c curl http://127.0.0.1:{port}/pwned | Out-Null",
            bad_chars=bad_chars,
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        replaced_code = stones.replace_instructions(code, bad_chars)
        shellcode = stones.assemble(replaced_code)
        self.assertFalse(any(c in bad_chars for c in shellcode))

        self.assertTrue(test_exec_command_shellcode(shellcode, port))
