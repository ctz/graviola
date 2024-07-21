import enum
import re
import glob
import string

MACRO = re.compile(r"^(?P<name>[a-z0-9_]+)\((?P<args>[a-z0-9_,\[\]\+\* \#]*)\);?$")
ASM = re.compile(
    r"^(?P<opcode>[a-z][a-z0-9\.]*)\s?(?P<operands>[A-Za-z0-9_,\s\(\)\[\]\+\*\-~\t#\.!%$]*) ?;? ?(//(?P<comment>[A-Za-z0-9 =\/#\*\+\(\)^\.\<\>\-_:,\!\?\|])*)?$"
)
DECL = re.compile(r"S2N_BN_SYMBOL\((?P<name>[a-z0-9_]+)\):")
CONST = re.compile(r"\s?(?P<type>\.(quad|long))\s+(?P<value>((0x[0-9a-fA-F]+),?)+)")
LABEL = re.compile(r"^(?P<name>(\.L)?[a-zA-Z0-9_]+):$")


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
    DIRECTIVE = enum.auto()
    EOF = enum.auto()


def tidy_linewise(lines):
    # multiline fixups prior to parsing

    # remove cf-protection comment
    if (
        lines[-6] == '.section\t.note.gnu.property,"a",@note\n'
        and lines[-5] == "\t.long\t4,2f-1f,5\n"
        and lines[-4] == "\t.byte\t0x47,0x4E,0x55,0\n"
        and lines[-3] == "1:\t.long\t0xc0000002,4,3\n"
        and lines[-2] == ".align\t8\n"
        and lines[-1] == "2:\n"
    ):
        lines = lines[:-6]

    return lines


def parse_file(f, visit):
    continuation = None
    contexts = []

    lines = f.readlines()
    lines = tidy_linewise(lines)

    for l in lines:
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
            for v in m.group("value").split(","):
                visit(Type.CONST, contexts, m.group("type"), v)
        elif l.startswith(".balign 4"):
            visit(Type.ALIGN, contexts, "4")
        elif l.strip().startswith("."):
            parts = [x.strip() for x in l.strip().split()]
            visit(Type.DIRECTIVE, contexts, *parts)
        else:
            raise ValueError("UNHANDLED line " + repr(l))

    visit(Type.EOF)


def is_comment(s):
    s = s.strip()
    return s.startswith("/*") and s.endswith("*/")


def tokenise(s):
    def tokenise_gen(s):
        symbol = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*")
        register = re.compile(r"^%?[a-z]\.?[a-z0-9]+(\.[a-z]\[\d+\]|\.[a-z0-9]+)?")
        label = re.compile(r"^\.?[a-zA-Z][a-zA-Z0-9_]+")
        comment = re.compile(r"^/\*.*?\*/")
        number = re.compile(r"^[\$#]?(-?0x[0-9a-fA-F]+|-?[0-9]+)")
        operator = re.compile(r'^["\(\)\[\]\+\*/\-,;:#\.!]')
        whitespace = re.compile(r"^\s+")

        while s:
            longest_pat = None
            longest_match = None

            for pat in (symbol, register, label, comment, number, operator, whitespace):
                m = pat.match(s)
                if m:
                    if (longest_match is None) or (
                        longest_match is not None and m.end() > longest_match.end()
                    ):
                        longest_pat = pat
                        longest_match = m

            if longest_match is not None:
                # print('match', longest_pat, longest_match.group())
                if longest_pat != whitespace:
                    yield longest_match.group()
                s = s[longest_match.end() :]
                continue

            print("failed to match", repr(s))
            raise ValueError()

    x = list(tokenise_gen(s))
    return x


def extract_header_comment(file):
    comment_lines = []

    for line in file.readlines():
        if line.startswith("#!"):
            continue
        elif line.startswith("#"):
            comment_lines.append(line.rstrip().lstrip("# "))
        else:
            break

    return comment_lines
