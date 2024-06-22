import enum
import re
import glob

MACRO = re.compile(r"^(?P<name>[a-z0-9_]+)\((?P<args>[a-z0-9_,\[\]\+\*]+)\);?$")
ASM = re.compile(
    r"^(?P<opcode>[a-z0-9]+) ?(?P<operands>[A-Za-z0-9_, \(\)\[\]\+\*\-~\t]*) ?(//(?P<comment>[A-Za-z0-9 =\*\+\(\)^\.\<\>\-:,\!\?])*)?$"
)
DECL = re.compile(r"S2N_BN_SYMBOL\((?P<name>[a-z0-9_]+)\):")
CONST = re.compile(r"(?P<type>\.quad) +(?P<value>0x[0-9a-fA-F]+)")
LABEL = re.compile(r"^(?P<name>[a-z0-9_]+):$")


class Type(enum.StrEnum):
    COMMENT = enum.auto()
    DEFINE = enum.auto()
    VERTICAL_WHITESPACE = enum.auto()
    MACRO = enum.auto()
    ASM = enum.auto()
    CONST = enum.auto()
    FUNCTION = enum.auto()
    ALIGN = enum.auto()
    LABEL = enum.auto()


def parse_file(f, visit):
    continuation = None
    contexts = []

    for l in f.readlines():
        l = l.lstrip()

        if continuation:
            lr = l.rstrip().rstrip("\\").rstrip()
            if l.endswith("\\\n"):
                continuation.append(lr)
                continue
            else:
                continuation.append(lr)
                visit(*continuation)
                continuation = None
                continue

        if l.startswith("// "):
            visit(Type.COMMENT, l[3:])
        elif l.startswith("//"):
            visit(Type.COMMENT, l[2:])
        elif l.startswith("#define "):
            def_, name, val = l.split(maxsplit=2)
            val = val.rstrip().rstrip("\\").rstrip()

            if l.endswith("\\\n"):
                continuation = [Type.DEFINE, name.strip(), val]
            else:
                visit(Type.DEFINE, name.strip(), val)
        elif l.startswith(".set"):
            _, name, value = l.split()
            visit(Type.DEFINE, name.strip(), value.strip())
        elif l.startswith("#endif"):
            contexts.pop()
        elif l.startswith("#if WINDOWS_ABI"):
            contexts.append("WINDOWS_ABI")
        elif l.startswith("#if defined(__linux__) && defined(__ELF__)"):
            contexts.append("LINUX_ELF")
        elif l.startswith(".rep"):
            _, arg = l.split()
            contexts.append(("REP", int(arg)))
        elif l.startswith(".endr"):
            contexts.pop()
        elif l.replace(", ", ",").startswith('.section .note.GNU-stack,"",%progbits'):
            continue
        elif l.startswith("#include "):
            continue
        elif l.startswith(".intel_syntax noprefix"):
            continue
        elif l.startswith(".text"):
            continue
        elif l.startswith("S2N_BN_SYM_VISIBILITY_DIRECTIVE("):
            continue
        elif l.startswith("S2N_BN_SYM_PRIVACY_DIRECTIVE("):
            continue
        elif l.strip() == "":
            visit(Type.VERTICAL_WHITESPACE)
        elif l.startswith("# "):
            visit(Type.COMMENT, l[2:])
        elif MACRO.match(l):
            m = MACRO.match(l)
            visit(Type.MACRO, m.group("name"), m.group("args"))
        elif LABEL.match(l):
            m = LABEL.match(l)
            visit(Type.LABEL, contexts, m.group("name"))
        elif ASM.match(l):
            m = ASM.match(l)
            visit(
                Type.ASM,
                contexts,
                m.group("opcode").strip(),
                m.group("operands").strip(),
            )
        elif DECL.match(l):
            m = DECL.match(l)
            visit(Type.FUNCTION, contexts, m.group("name"))
        elif CONST.match(l):
            m = CONST.match(l)
            visit(Type.CONST, contexts, m.group("type"), m.group("value"))
        elif l.startswith(".balign 4"):
            visit(Type.ALIGN, contexts, "4")
        else:
            raise ValueError("UNHANDLED line " + repr(l))


# parse_file(open('curve25519_x25519.S'), lambda *x: print(x))
# parse_file(open('p256_montjadd.S'), lambda *x: print(x))

"""
for f in glob.glob('../../s2n-bignum/x86/*/*.S'):
    if 'proofs' in f:
        continue
    print('FILE:', f)
    parse_file(open(f), lambda *x: print(x))
"""
