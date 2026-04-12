import enum
import re
from typing import Generator, NamedTuple


class Type(enum.StrEnum):
    Int = enum.auto()
    Char = enum.auto()
    Ident = enum.auto()
    Op = enum.auto()
    LParen = enum.auto()
    RParen = enum.auto()
    Comma = enum.auto()


class Token(NamedTuple):
    type: Type
    value: object  # int for INT/CHAR, str for everything else


# integer suffixes – any combination of u/U and l/L/ll/LL, in either order
_INT_SUFFIX = r"(?:[uU](?:ll?|LL?)?|(?:ll?|LL?)[uU]?)?"

_PATTERNS: list[tuple[str, re.Pattern]] = [
    # whitespace – no token emitted
    ("WS", re.compile(r"[ \t\r\n\f\v]+")),
    # hex literal  0x1A2B / 0X1a2b
    ("HEX", re.compile(r"0[xX]([0-9A-Fa-f]+)" + _INT_SUFFIX, re.ASCII)),
    # binary literal  0b1010  (GCC extension, widely supported)
    ("BIN", re.compile(r"0[bB]([01]+)" + _INT_SUFFIX, re.ASCII)),
    # octal literal  0777
    ("OCT", re.compile(r"(0[0-7]*)" + _INT_SUFFIX, re.ASCII)),
    # decimal literal  (must come after 0-prefixed ones)
    ("DEC", re.compile(r"([1-9][0-9]*)" + _INT_SUFFIX, re.ASCII)),
    # character literal  'x'  '\n'  '\xNN'  '\0NN'
    (
        "CHAR",
        re.compile(
            r"L?'("
            r"\\(?:[abfnrtvx\\\'\"?]|[0-7]{1,3}|x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})"
            r"|[^\'\\]"
            r")'"
        ),
    ),
    # identifiers (including "defined")
    ("IDENT", re.compile(r"[A-Za-z_]\w*", re.ASCII)),
    # two-character operators (must precede single-char)
    ("OP2", re.compile(r"<<|>>|&&|\|\||==|!=|<=|>=")),
    # single-character operators
    ("OP1", re.compile(r"[+\-*/%~!&|^<>?:]")),
    # punctuation
    ("LPAREN", re.compile(r"\(")),
    ("RPAREN", re.compile(r"\)")),
    ("COMMA", re.compile(r",")),
]

# ── character-escape decoder ───────────────────────────────────────────────────

_SIMPLE_ESCAPES: dict[str, int] = {
    "a": 0x07,
    "b": 0x08,
    "f": 0x0C,
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "v": 0x0B,
    "\\": 0x5C,
    "'": 0x27,
    '"': 0x22,
    "?": 0x3F,
}


def _decode_char_escape(raw: str) -> int:
    """Turn the *content* of a character literal (after outer quotes) into an int."""
    if not raw.startswith("\\"):
        return ord(raw)
    esc = raw[1:]
    if esc in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[esc]
    if esc.startswith(("x", "u", "U")):
        return int(esc[1:], 16)
    # octal
    return int(esc, 8)


# ── main tokeniser ─────────────────────────────────────────────────────────────


def tokenise(source: str) -> Generator[Token, None, None]:
    """
    Yield Token objects for every meaningful token in a C preprocessor
    conditional expression string (the text that follows ``#if``).

    Raises ``SyntaxError`` on any character that cannot be matched.
    """
    pos = 0
    length = len(source)

    while pos < length:
        for tag, pattern in _PATTERNS:
            m = pattern.match(source, pos)
            if m is None:
                continue

            if tag == "WS":
                pass  # consume silently

            elif tag == "HEX":
                yield Token(Type.Int, int(m.group(1), 16))

            elif tag == "BIN":
                yield Token(Type.Int, int(m.group(1), 2))

            elif tag == "OCT":
                yield Token(Type.Int, int(m.group(1), 8))

            elif tag == "DEC":
                yield Token(Type.Int, int(m.group(1), 10))

            elif tag == "CHAR":
                yield Token(Type.Char, _decode_char_escape(m.group(1)))

            elif tag == "IDENT":
                yield Token(Type.Ident, m.group(0))

            elif tag in ("OP1", "OP2"):
                yield Token(Type.Op, m.group(0))

            elif tag == "LPAREN":
                yield Token(Type.LParen, "(")

            elif tag == "RPAREN":
                yield Token(Type.RParen, ")")

            elif tag == "COMMA":
                yield Token(Type.Comma, ",")

            pos = m.end()
            break
        else:
            raise SyntaxError(f"Unexpected character {source[pos]!r} at position {pos}")


class Preprocessor:
    def __init__(self):
        self.defs = dict()
        self.funcs = dict()

    def set(self, key, value):
        self.defs[key] = value

    def function(self, name, value_fn):
        self.funcs[name] = value_fn

    def _eval_expr_truth(self, t, d=0):
        result = None
        while t:
            e = t.pop(0)

            if e.type == Type.Int:
                result = e.value > 0
            elif e.type == Type.Ident and e.value == "defined":
                assert t.pop(0).type == Type.LParen
                item = t.pop(0)
                assert t.pop(0).type == Type.RParen
                assert item.type == Type.Ident
                result = item.value in self.defs
            elif e.type == Type.Ident:
                value = self.defs.get(e.value, 0)
                try:
                    result = int(value, 0) > 0
                except:
                    result = False
            elif e.type == Type.LParen:
                depth = 1
                sub_e = []
                while t:
                    e = t.pop(0)
                    if e.type == Type.LParen:
                        depth += 1
                    elif e.type == Type.RParen:
                        depth -= 1
                        if depth == 0:
                            break
                    sub_e.append(e)
                result = self._eval_expr_truth(sub_e, d=d + 2)
            elif e.type == Type.Op:
                if e.value == "&&":
                    if not result:
                        return False
                    return self._eval_expr_truth(t, d=d + 2)
                elif e.value == "||":
                    result |= self._eval_expr_truth(t, d=d + 2)
                else:
                    print(f"unhandled op {e}")
            else:
                print(f"no idea how to evaluate {e}")
                return False

        return result

    def evaluate_expression(self, expr):
        return self._eval_expr_truth(list(tokenise(expr)))

    def apply_lines(self, lines):
        r = []
        skipping = False

        for l in lines:
            l = l.lstrip()

            if l.startswith("#if "):
                _if, expr = l.split(" ", maxsplit=1)
                skipping = not self.evaluate_expression(expr)
                continue
            elif l.startswith("#elif "):
                _elif, expr = l.split(" ", maxsplit=1)
                skipping = not skipping and self.evaluate_expression(expr)
                continue
            elif l.startswith("#else"):
                skipping = not skipping
                continue
            elif l.startswith("#endif"):
                skipping = False
                continue

            def splat(groups):
                items = groups.split(",")
                items = [item.strip() for item in items]
                items = [item for item in items if item != ""]
                return items

            if not skipping:
                for k, v in self.defs.items():
                    l = re.sub("\\b" + k + "\\b", v, l)
                for k, f in self.funcs.items():
                    l = re.sub(
                        r"\b" + k + "\\(([^)]*)\\)",
                        lambda m: f(*splat(m.group(1))),
                        l,
                    )

                r.append(l)

        return r


if __name__ == "__main__":
    tests = [
        ("1", [Type.Int]),
        ("0xFF", [Type.Int]),
        ("0b1010", [Type.Int]),
        ("0777", [Type.Int]),
        ("'\\n'", [Type.Char]),
        ("defined(FOO)", [Type.Ident, Type.LParen, Type.Ident, Type.RParen]),
        ("A && !B || 0", [Type.Ident, Type.Op, Type.Op, Type.Ident, Type.Op, Type.Int]),
        (
            "(X << 2) >= 0x10ULL",
            [
                Type.LParen,
                Type.Ident,
                Type.Op,
                Type.Int,
                Type.RParen,
                Type.Op,
                Type.Int,
            ],
        ),
    ]

    for expr, expected_types in tests:
        tokens = list(tokenise(expr))
        actual_types = [t.type for t in tokens]
        if actual_types != expected_types:
            print(f"    expected {expected_types}")
            print(f"    got      {actual_types}")
        assert actual_types == expected_types

    for expr in [
        "defined(NDEBUG) && (LEVEL >= 0x10UL || !VERBOSE)",
        "defined(__linux__) && defined(__ELF__)",
    ]:
        print(f"Tokens for: {expr!r}")
        for tok in tokenise(expr):
            print(f"  {tok}")

    p = Preprocessor()
    p.set("A", "1")
    p.function("YYY", lambda *args: str(len(args)))

    assert p.apply_lines(["#if A", "OK", "#endif"]) == ["OK"]
    assert p.apply_lines(["#if A && A", "OK", "#endif"]) == ["OK"]
    assert p.apply_lines(["#if A || A", "OK", "#endif"]) == ["OK"]
    assert p.apply_lines(["#if defined(A) && A", "OK", "#endif"]) == ["OK"]
    assert p.apply_lines(["#if defined(A) && defined(X)", "OK", "#endif"]) == []
    assert p.apply_lines(["#if defined(A) || A", "OK", "#endif"]) == ["OK"]
    assert p.apply_lines(["#if A && NOTSET", "OK", "#endif"]) == []
    assert p.apply_lines(["#if (A && NOTSET) || (A && A)", "OK", "#endif"]) == ["OK"]
    assert p.apply_lines(["#if NOTSET", "ERR", "#else", "OK", "#endif"]) == ["OK"]

    assert p.apply_lines(["echo A"]) == ["echo 1"]
    assert p.apply_lines(["echoA"]) == ["echoA"]

    assert p.apply_lines(["YYY"]) == ["YYY"]
    assert p.apply_lines(["YYY()"]) == ["0"]
    assert p.apply_lines(["YYY(a)"]) == ["1"]
    assert p.apply_lines(["YYY(a,b)"]) == ["2"]
    assert p.apply_lines(["YYY(a, b)"]) == ["2"]
