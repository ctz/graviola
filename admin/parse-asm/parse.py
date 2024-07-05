import enum
import re
import glob
import string

MACRO = re.compile(r"^(?P<name>[a-z0-9_]+)\((?P<args>[a-z0-9_,\[\]\+\* \#]*)\);?$")
ASM = re.compile(
    r"^(?P<opcode>[a-z][a-z0-9\.]*) ?(?P<operands>[A-Za-z0-9_, \(\)\[\]\+\*\-~\t#\.!]*) ?;? ?(//(?P<comment>[A-Za-z0-9 =\/#\*\+\(\)^\.\<\>\-_:,\!\?\|])*)?$"
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
    EOF = enum.auto()


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
            _def, name, val = l.split(maxsplit=2)
            if len(tokenise(name)) != 1:
                # needs full tokenisation
                l_without_continuation = l.rstrip().rstrip("\\").rstrip()
                tokens = tokenise(l_without_continuation)
                assert tokens[0] == "#"
                assert tokens[1] == "define"
                tokens = tokens[2:]

                name = tokens[0]
                if len(tokens) == 2:
                    val = tokens[1]
                elif tokens[1] == "(":
                    end = tokens.index(")")
                    name += "".join(tokens[1 : end + 1])
                    val = ""
                else:
                    val = "".join(tokens[1])

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

    visit(Type.EOF)


def is_comment(s):
    s = s.strip()
    return s.startswith("/*") and s.endswith("*/")


def tokenise(s):
    def tokenise_gen(s):
        run = None
        run_type = None

        letters = string.ascii_letters
        symbol = string.ascii_letters + string.digits + "_"
        register_open = symbol + ".["
        register_close = register_open + "]"
        hex = string.hexdigits + "x"
        numbers = string.digits
        comment = []

        if is_comment(s):
            yield s
            return

        i = 0
        while i < len(s):
            x = s[i]
            next = s[i + 1] if i + 1 < len(s) else None
            i += 1

            if x == "/" and next == "*":
                run = x
                run_type = comment
                continue

            if run_type == comment:
                run = run + x

                if x == "*" and next == "/":
                    run = run + next
                    i += 1
                    yield run
                    run = None
                    run_type = None
                continue

            if x == "#" and next == "0":
                run_type = hex
                run = x
                continue

            if x == "x" and run == "0" and run_type == numbers:
                run_type = hex
                run = run + x
                continue

            if run_type == letters and x not in run_type and x in symbol:
                run_type = symbol

            if (
                run_type in (letters, symbol)
                and x not in run_type
                and x in register_open
            ):
                run_type = register_open

            if run_type == register_open and x not in run_type and x in register_close:
                run_type = register_close

            if run_type is not None and x not in run_type:
                yield run
                run = None
                run_type = None

            if run_type is not None and x in run_type:
                run = run + x
                continue

            if x in string.whitespace:
                continue

            if x in "()[]+*/-,;#.!":
                yield x
                continue

            if x in numbers:
                run = x
                run_type = numbers
                continue

            if x in letters:
                run = x
                run_type = letters
                continue

            print("UNHANDLED tokenise " + x)

        if run_type is not None:
            yield run

    return list(tokenise_gen(s))
