import enum
import re   

SYMBOL = re.compile(r'[a-z0-9_]+')
MACRO = re.compile(r'(?P<name>[a-z0-9_]+)\((?P<args>[a-z0-9_,]+)\)')
ASM = re.compile(r'(?P<opcode>[a-z0-9]+) (?P<operands>[A-Za-z0-9_, ]*)')

class Type(enum.StrEnum):
    COMMENT = enum.auto()
    INTEL_SYNTAX = enum.auto()
    TEXT_SECTION = enum.auto()
    DEFINE = enum.auto()
    VERTICAL_WHITESPACE = enum.auto()
    MACRO = enum.auto()
    ASM = enum.auto()

def parse_file(f, visit):
    continuation = None

    for l in f.readlines():
        l = l.lstrip()

        if continuation:
            lr = l.rstrip().rstrip('\\').rstrip()
            if l.endswith('\\\n'):
                continuation.append(lr)
                continue
            else:
                continuation.append(lr)
                visit(*continuation)
                continuation = None
                continue

        if l.startswith('// '):
            visit(Type.COMMENT, l[3:])
        elif l.startswith('//'):
            visit(Type.COMMENT, l[2:])
        elif l.startswith('#define '):
            def_, name, val = l.split(maxsplit=2)
            val = val.rstrip().rstrip('\\').rstrip()

            if l.endswith('\\\n'):
                continuation = [Type.DEFINE, name.strip(), val]
            else:
                visit(Type.DEFINE, name.strip(), val)
        elif l.startswith('#include '):
            continue
        elif l.startswith('.intel_syntax noprefix'):
            visit(Type.INTEL_SYNTAX)
        elif l.startswith('.text'):
            visit(Type.TEXT_SECTION)
        elif l.startswith('S2N_BN_SYM_VISIBILITY_DIRECTIVE('):
            continue
        elif l.startswith('S2N_BN_SYM_PRIVACY_DIRECTIVE('):
            continue
        elif l.strip() == '':
            visit(Type.VERTICAL_WHITESPACE)
        elif MACRO.match(l):
            m = MACRO.match(l)
            visit(Type.MACRO, m.group('name'), m.group('args'))
        elif ASM.match(l):
            m = ASM.match(l)
            visit(Type.ASM, m.group('opcode'), m.group('operands'))
        else:
            print('UNHANDLED', l)


parse_file(open('p256_montjadd.S'), lambda *x: print(x))
