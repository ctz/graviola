import string
from functools import reduce

from parse import Type


class Architecture:
    # registers (canonically named via `lookup_register`)
    # that should be ignored when calculating clobbers
    ignore_clobber = set()

    # canonicalise register names, by returning a better name
    # for `reg`.
    #
    # return `None` if `reg` is not a recognised register name.
    @staticmethod
    def lookup_register(reg):
        pass


class Architecture_amd64(Architecture):
    """
    x86	ax	eax, rax
    x86	bx	ebx, rbx
    x86	cx	ecx, rcx
    x86	dx	edx, rdx
    x86	si	esi, rsi
    x86	di	edi, rdi
    x86	bp	bpl, ebp, rbp
    x86	sp	spl, esp, rsp
    x86	ip	eip, rip
    x86	st(0)	st
    x86	r[8-15]	r[8-15]b, r[8-15]w, r[8-15]d
    x86	xmm[0-31]	ymm[0-31], zmm[0-31]
    """

    ignore_clobber = set("rbx rsp rbp".split())

    @staticmethod
    def lookup_register(reg):
        for c in "ax bx cs dx si di ip".split():
            if reg in [c, "e" + c, "r" + c]:
                return "r" + c

        for c in "bp sp".split():
            if reg in [c, c + "l", "e" + c, "r" + c]:
                return "r" + c

        if reg == "st":
            return reg

        for n in range(8, 16):
            n = str(n)
            if reg in ["r" + n, "r" + n + "b", "r" + n + "w", "r" + n + "b"]:
                return "r" + n

        for n in range(0, 32):
            n = str(n)
            if reg in ["xmm" + n, "ymm" + n, "zmm" + n]:
                return "zmm" + n


class Dispatcher:
    def __call__(self, ty, *args):
        func = getattr(self, "on_" + ty.lower())
        func(*args)

    def on_comment(self, comment):
        pass

    def on_vertical_whitespace(self):
        pass

    def on_define(self, name, *value):
        print("!!! UNHANDLED: on_define(", name, ",", value, ")")

    def on_function(self, contexts, name):
        print("!!! UNHANDLED: on_function(", contexts, ",", name, ")")

    def on_asm(self, contexts, opcode, operands):
        print("!!! UNHANDLED: on_asm(", contexts, ",", opcode, ",", operands, ")")

    def on_macro(self, name, operands):
        print("!!! UNHANDLED: on_macro(", name, ",", operands, ")")

    def on_label(self, contexts, label):
        print("!!! UNHANDLED: on_label(", contexts, ",", label, ")")


def tokenise(s):
    def tokenise_gen(s):
        run = None
        run_type = None

        symbol = string.ascii_letters + string.digits + "_"
        hex = string.hexdigits
        numbers = string.digits

        for x in s:
            if x == "x" and run == "0" and run_type == numbers:
                run_type = hex
                run = run + x
                continue

            if run_type is not None and x not in run_type:
                yield run
                run = None
                run_type = None

            if run_type is not None and x in run_type:
                run = run + x
                continue

            if x in string.whitespace:
                continue

            if x in "()[]+*/-,;":
                yield x
                continue

            if x in numbers:
                run = x
                run_type = numbers
                continue

            if x in symbol:
                run = x
                run_type = symbol
                continue

            print("UNHANDLED tokenise " + x)

        if run_type is not None:
            yield run

    return list(tokenise_gen(s))


def tokens_to_macro_fn(tokens):
    tokens = list(tokens)

    name = tokens.pop(0)
    assert tokens.pop(0) == "("
    params = []
    while len(tokens) > 1:
        params.append(tokens.pop(0))
        if len(tokens) > 1:
            assert tokens.pop(0) == ","
    assert tokens.pop(0) == ")"
    return name, params


class unquote:
    def __init__(self, v):
        self.v = v


def tokens_to_quoted_spans(tokens):
    tokens = list(tokens)
    collected = []
    while tokens:
        cur = tokens.pop(0)
        next = tokens[0] if len(tokens) else ""
        if isinstance(next, unquote):
            next = next.v

        if isinstance(cur, unquote):
            if collected:
                yield '"' + "".join(collected) + '"'
            collected = []
            yield cur.v
            continue

        if next in ",;])":
            collected.append(cur)
        elif cur == ";":
            collected.append(cur)
            yield '"' + "".join(collected) + '"'
            collected = []
        elif cur in "[(":
            collected.append(cur)
        else:
            collected.append(cur)
            collected.append(" ")

    if collected:
        yield '"' + "".join(collected) + '"'


def tokens_to_single_glued_string(tokens):
    return " ".join(tokens_to_quoted_spans(tokens))


def tokens_to_quoted_asm(tokens):
    return " ".join(tokens_to_quoted_spans(tokens))


def tokens_to_args(tokens):
    def gen(tokens):
        for t in tokens:
            if isinstance(t, unquote):
                yield t.v
            elif t == ",":
                continue
            else:
                yield '"' + t + '"'

    return ", ".join(gen(tokens))


if __name__ == "__main__":
    assert tokenise("1234+1235") == ["1234", "+", "1235"]
    assert tokenise("rsp+(3*NUMSIZE)") == ["rsp", "+", "(", "3", "*", "NUMSIZE", ")"]
    assert tokenise("mul_p25519(P0,P1,P2)") == [
        "mul_p25519",
        "(",
        "P0",
        ",",
        "P1",
        ",",
        "P2",
        ")",
    ]
    assert tokenise("add 0x1, 0x1234") == ["add", "0x1", ",", "0x1234"]
    print(tokenise("QWORD PTR [rsp+12*NUMSIZE+8]"))
