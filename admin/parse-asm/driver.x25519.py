import subprocess

from parse import Type, parse_file
from driver import (
    Architecture_amd64,
    Dispatcher,
    tokenise,
    tokens_to_macro_fn,
    tokens_to_quoted_asm,
    tokens_to_single_glued_string,
    tokens_to_args,
    unquote,
)


class Driver(Dispatcher):
    def __init__(self, output, architecture):
        super(Dispatcher, self).__init__()
        self.output = output
        self.arch = architecture
        self.rust_macros = {}
        self.parameter_map = []
        self.clobbers = set()
        self.start()

    def start(self):
        print(
            """
/// "comma concat": takes a sequence of expressions,
/// and feeds them into concat!() to form a single string
macro_rules! CC {
    ($($e:expr)*) => {
        concat!($($e ,)*)
    };
}
        """,
            file=self.output,
        )

    def register_rust_macro(self, name, value, params=None):
        self.rust_macros[name] = (value, params)

    def expand_rust_macros(self, *values, params={}):
        for v in values:
            for t in tokenise(v):
                if t in self.rust_macros:
                    assert self.rust_macros[t][1] == None
                    yield unquote("%s!()" % t)
                elif t in params:
                    yield unquote("$" + t)
                else:
                    yield t

    def expand_rust_macros_in_macro_decl(self, *values, params={}):
        return tokens_to_single_glued_string(
            self.expand_rust_macros(*values, params=params)
        )

    def expand_rust_macros_in_asm(self, *values):
        return tokens_to_quoted_asm(self.expand_rust_macros(*values))

    def expand_rust_macros_in_macro_call(self, *values):
        return tokens_to_args(self.expand_rust_macros(*values))

    def on_function(self, contexts, name):
        assert contexts == []
        if name == "curve25519_x25519":
            self.parameter_map = [
                ("inout", "rdi", "res.as_mut_ptr() => _"),
                ("inout", "rsi", "scalar.as_mut_ptr() => _"),
                ("inout", "rdx", "point.as_mut_ptr() => _"),
            ]

            print(
                """
            pub fn curve25519_x25519(res: &mut [u8; 32], scalar: &mut [u8; 32], point: &mut [u8; 32]) {
                unsafe { core::arch::asm!(
            """,
                file=self.output,
            )

    def on_comment(self, comment):
        print("// " + comment.rstrip(), file=self.output)

    def on_vertical_whitespace(self):
        print("", file=self.output)

    def on_define(self, name, *value):
        tokens = tokenise(name)
        if len(tokens) == 1:
            assert len(value) == 1
            self.register_rust_macro(tokens[0], value)
            value = self.expand_rust_macros_in_macro_decl(*value)
            print(
                """macro_rules! %s { () => { CC!(%s) } }""" % (tokens[0], value),
                file=self.output,
            )
        else:
            name, params = tokens_to_macro_fn(tokens)
            self.register_rust_macro(name, value, params)
            value = self.expand_rust_macros_in_macro_decl(*value, params=params)

            params = ["$%s:expr" % p for p in params]
            print(
                """macro_rules! %s { (%s) => { CC!(%s) } }"""
                % (name, ", ".join(params), value),
                file=self.output,
            )

    def on_asm(self, contexts, opcode, operands):
        if "WINDOWS_ABI" in contexts:
            # No need for these as we leave function entry/return to rustc
            return

        if opcode == "ret":
            return self.finish_function()

        self.visit_operands(operands)

        operands = self.expand_rust_macros_in_asm(operands)
        parts = ['"    %-10s"' % opcode]
        if operands:
            parts.append(operands)
        print(", ".join(parts) + ",", file=self.output)

    def visit_operands(self, operands):
        for t in tokenise(operands):
            actual_reg = self.arch.lookup_register(t)
            if actual_reg:
                self.clobbers.add(actual_reg)

    def on_label(self, contexts, label):
        if "WINDOWS_ABI" in contexts:
            return
        print('"    %s:",' % label, file=self.output)

    def on_macro(self, name, params):
        assert name in self.rust_macros
        value = self.expand_rust_macros_in_macro_call(params)
        print("%s!(%s)," % (name, value), file=self.output)

    def finish_function(self):
        for dir, reg, param in self.parameter_map:
            print('%s("%s") %s,' % (dir, reg, param), file=self.output)

        print("    // clobbers", file=self.output)
        for c in sorted(self.clobbers):
            if c in [x[1] for x in self.parameter_map]:
                continue
            if c in self.arch.ignore_clobber:
                continue
            print('    out("%s") _,' % c, file=self.output)

        self.clobbers = []
        self.parameter_map = []

        print("    )}", file=self.output)

    def finish_file(self):
        print("}", file=self.output)

        filename = self.output.name
        self.output.close()

        subprocess.check_call(["rustfmt", filename])


with open("curve25519_x25519.S") as input, open("c.rs", "w") as output:
    d = Driver(output, Architecture_amd64)
    parse_file(input, d)
    d.finish_file()
