import os
import time
import unittest
import uuid

from coder import exec_command
from runner import load_shellcode, run_shellcode
from stones import assemble


class TestExecCommand(unittest.TestCase):
    def test_run_shellcode(self):
        tmp_dir = ".\\tmp"
        test_file = str(uuid.uuid4())

        code = exec_command.generate(
            cmd=f"powershell -c mkdir tmp; echo pwned > {tmp_dir}\\{test_file}",
            bad_chars=b"\x00",
            exit_func=("ntdll.dll", "RtlExitUserThread"),
            debug=False,
        )
        shellcode = assemble(code)

        ptr = load_shellcode(shellcode)
        run_shellcode(ptr, wait=True)
        time.sleep(1)

        self.assertTrue(os.path.exists(f"{tmp_dir}\\{test_file}"))

        with open(f"{tmp_dir}\\{test_file}", "r", encoding="utf_16") as f:
            content = f.read()
        self.assertIn("pwned", content)

        os.remove(f"{tmp_dir}\\{test_file}")
        os.removedirs(tmp_dir)
