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
        self.labels = {}
        self.labels_defined = set()
        self.start()

    def start(self):
        print(
            """
/// takes a sequence of expressions, and feeds them into
/// concat!() to form a single string
///
/// named after perl's q operator. lol.
macro_rules! Q {
    ($($e:expr)*) => {
        concat!($($e ,)*)
    };
}

/// Label macro, which just resolves to the id as a string,
/// but keeps the name close to it in the code.
macro_rules! Label {
    ($name:literal, $id:literal) => {
        stringify!($id)
    };

    ($name:literal, $id:literal, After) => {
        stringify!($id f)
    };

    ($name:literal, $id:literal, Before) => {
        stringify!($id b)
    }
}
        """,
            file=self.output,
        )

    def find_label(self, label, defn=False):
        """
        Returns an ordinal "local label" for the name `label`

        Returns (ordinal, defined_before).

        `defined_before` is true if the label is already defined.
        """
        if defn:
            self.labels_defined.add(label)

        id = self.labels.get(label, None)
        if id is not None:
            return id, label in self.labels_defined

        # workaround warning that numeric labels must not solely
        # consist of '1' and '0' characters. unhinged!
        next_id = max(self.labels.values()) + 1 if self.labels else 1
        while len(str(next_id).replace("1", "").replace("0", "")) == 0:
            next_id += 1

        self.labels[label] = next_id
        return next_id, label in self.labels_defined

    def looks_like_label(self, label):
        return label.startswith("curve25519_")

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
                elif t in self.labels or self.looks_like_label(t):
                    id, before = self.find_label(t)
                    yield unquote(
                        'Label!("%s", %d, %s)'
                        % (t, id, "Before" if before else "After")
                    )
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
                ("inout", "rsi", "scalar.as_ptr() => _"),
                ("inout", "rdx", "point.as_ptr() => _"),
            ]

            print(
                """
            pub fn curve25519_x25519(res: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
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
                """macro_rules! %s { () => { Q!(%s) } }""" % (tokens[0], value),
                file=self.output,
            )
        else:
            name, params = tokens_to_macro_fn(tokens)
            self.register_rust_macro(name, value, params)
            value = self.expand_rust_macros_in_macro_decl(*value, params=params)

            params = ["$%s:expr" % p for p in params]
            print(
                """macro_rules! %s { (%s) => { Q!(%s) } }"""
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
        if operands:
            parts = ['"    %-10s"' % opcode]
            parts.append(operands)
            print("Q!(" + (" ".join(parts)) + "),", file=self.output)
        else:
            print("    %-10s" % opcode, file=self.output)

    def visit_operands(self, operands):
        for t in tokenise(operands):
            actual_reg = self.arch.lookup_register(t)
            if actual_reg:
                self.clobbers.add(actual_reg)

    def on_label(self, contexts, label):
        if "WINDOWS_ABI" in contexts:
            return
        id, _ = self.find_label(label, defn=True)
        print('Q!(Label!("%s", %d) ":"),' % (label, id), file=self.output)

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
        self.labels = {}

        print("    )}", file=self.output)

    def finish_file(self):
        print("}", file=self.output)

        filename = self.output.name
        self.output.close()

        subprocess.check_call(["rustfmt", filename])


with open("curve25519_x25519.S") as input, open(
    "../curve25519/src/low/x86_64.rs", "w"
) as output:
    d = Driver(output, Architecture_amd64)
    parse_file(input, d)
    d.finish_file()
