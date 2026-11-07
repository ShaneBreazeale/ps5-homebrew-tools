#!/usr/bin/env python3
"""Write a deterministic source fingerprint header; leave timestamps alone if unchanged.

This identifies debugger source inputs and LLVM version, not the final ELF or
its runtime validation. Record the ELF hash and build flags in the run manifest.
"""
import argparse
import hashlib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
INPUTS = ["mk/payloads.mk", "tooling/debugger_build_id.py",
          "vendor/prosper0gdb/rsp_transport.h", "vendor/prosper0gdb/trap_state.h"]
INPUTS += [str(p.relative_to(ROOT)) for p in sorted((ROOT / "payloads/process-debugger").glob("*"))
           if p.suffix in {".c", ".h"}]


def source_id(llvm_version):
    digest = hashlib.sha256()
    for name in INPUTS:
        data = (ROOT / name).read_bytes()
        digest.update(name.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
    digest.update(b"llvm\0" + llvm_version.encode())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--llvm-version", required=True)
    args = parser.parse_args()
    if not args.llvm_version or any(c not in "0123456789.-" for c in args.llvm_version):
        parser.error("LLVM version must contain only digits, dots and hyphens")
    text = ('/* Generated; source/LLVM fingerprint, not ELF identity. */\n'
            '#define PROCESS_DEBUGGER_BUILD_ID "' + source_id(args.llvm_version) + '"\n'
            '#define PROCESS_DEBUGGER_LLVM "' + args.llvm_version + '"\n')
    if not args.output.exists() or args.output.read_text() != text:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)


if __name__ == "__main__":
    main()
