"""Strict input helpers for offline analysis tools (Python standard library only)."""
import ast
import json
import re
import struct
from pathlib import Path

U64 = 1 << 64


def integer(value):
    if isinstance(value, bool):
        raise ValueError('boolean is not an integer')
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError('expected integer or integer string')


def load_table(path):
    text = Path(path).read_text()
    if Path(path).suffix == '.json':
        obj = json.loads(text)
        if not isinstance(obj, dict) or not obj:
            raise ValueError('table must be a nonempty JSON object')
        return {name: integer(value) for name, value in obj.items()}
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    # Accept the conventional single-table wrapper, not arbitrary C conditionals.
    text = re.sub(r'\A\s*#ifndef\s+(\w+)\s*\n\s*#define\s+\1\s*\n(.*)\n\s*#endif\s*\Z', r'\2', text, flags=re.S)
    defs = {}
    for line in text.splitlines():
        if not line.strip() or re.fullmatch(r'\s*(?:#include\s+[<\"][^>\"]+[>\"]|START_FW\(\d+\)|END_FW\(\))\s*', line):
            continue
        match = re.fullmatch(r'\s*DEF\(\s*([A-Za-z_]\w*)\s*,\s*(.*?)\s*\)\s*;?\s*', line)
        if not match:
            raise ValueError(f'unsupported table line: {line[:100]}')
        name, expression = match.groups()
        if name in defs:
            raise ValueError(f'duplicate symbol: {name}')
        defs[name] = expression
    if not defs:
        raise ValueError('no DEF entries found')
    resolved = {}
    def resolve(name, seen=()):
        if name in seen:
            raise ValueError(f'cyclic definition: {name}')
        if name not in defs:
            raise ValueError(f'undefined symbol: {name}')
        if name in resolved:
            return resolved[name]
        def visit(node):
            if isinstance(node, ast.Constant) and type(node.value) is int:
                return node.value
            if isinstance(node, ast.Name):
                return resolve(node.id, seen + (name,))
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
                value = visit(node.operand)
                return -value if isinstance(node.op, ast.USub) else value
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
                left, right = visit(node.left), visit(node.right)
                return left + right if isinstance(node.op, ast.Add) else left - right
            raise ValueError(f'unsupported expression for {name}')
        resolved[name] = visit(ast.parse(defs[name], mode='eval').body)
        return resolved[name]
    return {name: resolve(name) for name in defs}


def elf_loads(data):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected little-endian ELF64, version 1')
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, version, _, phoff, _, _, ehsize, stride, count, _, _, _ = header
    if kind not in (2, 3, 0xfe10) or machine != 62 or version != 1 or ehsize != 64:
        raise ValueError('expected x86-64 executable, shared-object, or captured 0xfe10 ELF')
    if not count or count == 65535 or stride != 56 or phoff < 64 or phoff + stride * count > len(data):
        raise ValueError('invalid or unsupported program header table')
    loads = []
    for index in range(count):
        kind, flags, off, va, _, size, memsize, align = struct.unpack_from('<IIQQQQQQ', data, phoff + stride * index)
        if kind != 1:
            continue
        if size > memsize or off + size > len(data) or va + memsize > U64:
            raise ValueError('PT_LOAD exceeds file or address bounds')
        if align not in (0, 1) and (align & (align - 1) or off % align != va % align):
            raise ValueError('invalid PT_LOAD alignment')
        if size:
            if any(va < oldva + oldsize and oldva < va + size for oldva, _, oldsize in loads):
                raise ValueError('overlapping file-backed PT_LOAD address ranges')
            loads.append((va, off, size))
    if not loads:
        raise ValueError('ELF has no file-backed PT_LOAD segments')
    return loads
