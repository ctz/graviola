import subprocess

from parse import Type, parse_file
from driver import (
    Architecture_amd64,
    Dispatcher,
    tokenise,
    tokens_to_macro_fn,
    tokens_to_quoted_asm,
    tokens_to_single_glued_string,
    tokens_to_single_glued_string_lines,
    tokens_to_args,
    unquote,
)

class ConstantArray:
    def __init__(self, name):
        self.name = name
        self.type = None
        self.items = []
        self.lines = []

    def add_comment(self, comment):
        self.lines.append('// ' + comment)

    def add_vertical_whitespace(self):
        self.lines.append('')

    def add_item(self, value):
        self.lines.append(value + ',')
        self.items.append(value)

    def set_type(self, type):
        if self.type is not None and self.type != type:
            raise ValueError('type varied within constant array')

        self.type = type


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
        self.constant_syms = set()
        self.current_constant_array = None
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

    def add_const_symbol(self, sym):
        self.constant_syms.add(sym)

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
                elif t in self.constant_syms:
                    yield "{" + t + "}"
                elif t in self.labels or self.looks_like_label(t):
                    id, before = self.find_label(t)
                    yield unquote(
                        'Label!("%s", %d, %s)'
                        % (t, id, "Before" if before else "After")
                    )
                else:
                    yield t

    def expand_rust_macros_in_macro_decl(self, *values, indent=0, params={}):
        if indent == 0:
            return tokens_to_single_glued_string(
                self.expand_rust_macros(*values, params=params)
            )
        else:
            return tokens_to_single_glued_string_lines(
                self.expand_rust_macros(*values, params=params), indent=indent
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
                ("in", "rsi", "scalar.as_ptr()"),
                ("in", "rdx", "point.as_ptr()"),
            ]

            print(
                """
            pub fn curve25519_x25519(res: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
                unsafe { core::arch::asm!(
            """,
                file=self.output,
            )
        elif name == 'curve25519_x25519base':
            self.parameter_map = [
                ('inout', 'rdi', "res.as_mut_ptr() => _"),
                ("in", "rsi", "scalar.as_ptr()"),
            ]

            print(
                """
            pub fn curve25519_x25519base(res: &mut [u8; 32], scalar: &[u8; 32]) {
                unsafe { core::arch::asm!(
            """,
                file=self.output,
            )

    def on_comment(self, comment):
        if self.current_constant_array:
            return self.current_constant_array.add_comment(comment.rstrip())

        print("// " + comment.rstrip(), file=self.output)

    def on_vertical_whitespace(self):
        if self.current_constant_array:
            return self.current_constant_array.add_vertical_whitespace()

        print("", file=self.output)

    def on_define(self, name, *value):
        tokens = tokenise(name)
        if len(tokens) == 1:
            assert len(value) == 1
            self.register_rust_macro(tokens[0], value)
            value = self.expand_rust_macros_in_macro_decl(*value, indent=0)
            print(
                """macro_rules! %s { () => { Q!(%s) } }""" % (tokens[0], value),
                file=self.output,
            )
        else:
            name, params = tokens_to_macro_fn(tokens)
            self.register_rust_macro(name, value, params)
            value = self.expand_rust_macros_in_macro_decl(
                *value, params=params, indent=8
            )

            params = ["$%s:expr" % p for p in params]
            print(
                """macro_rules! %s {
    (%s) => { Q!(
%s
    )}
}"""
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

        # TODO: need to visit_operands() in macro expansions
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
        if label in self.constant_syms:
            self.finish_constant_array()
            self.start_constant_array(label)
            return

        id, _ = self.find_label(label, defn=True)
        print('Q!(Label!("%s", %d) ":"),' % (label, id), file=self.output)

    def on_macro(self, name, params):
        assert name in self.rust_macros
        value = self.expand_rust_macros_in_macro_call(params)
        print("%s!(%s)," % (name, value), file=self.output)

    def on_const(self, contexts, type, value):
        self.emit_constant_item(type, value)

    def start_constant_array(self, name):
        self.current_constant_array = ConstantArray(name)

    def emit_constant_item(self, type, value):
        self.current_constant_array.set_type(type)
        self.current_constant_array.add_item(value)

    def finish_constant_array(self):
        if self.current_constant_array:
            ca = self.current_constant_array
            self.current_constant_array = None

            rust_type = {
                '.quad': 'u64',
            }[ca.type]

            print('static %s: [%s; %d] = [' % (ca.name, rust_type, len(ca.items)), file=self.output)
            for line in ca.lines:
                print('    %s' % line, file=self.output)
            print('];', file=self.output)
            print('', file=self.output)

    def finish_function(self):
        for dir, reg, param in self.parameter_map:
            print('%s("%s") %s,' % (dir, reg, param), file=self.output)

        if self.constant_syms:
            for c in self.constant_syms:
                print('%s = sym %s,' % (c, c), file=self.output)


        print("// clobbers", file=self.output)
        for c in sorted(self.clobbers):
            if c in [x[1] for x in self.parameter_map]:
                continue
            if c in self.arch.ignore_clobber:
                continue
            print('out("%s") _,' % c, file=self.output)

        self.clobbers = []
        self.parameter_map = []
        self.labels = {}

        print("    )}", file=self.output)
        print("}", file=self.output)

    def finish_file(self):
        self.finish_constant_array()

        filename = self.output.name
        self.output.close()

        subprocess.check_call(["rustfmt", filename])


with open("../../s2n-bignum/x86/curve25519/curve25519_x25519.S") as input, open(
    "../curve25519/src/low/x86_64/curve25519_x25519.rs", "w"
) as output:
    d = Driver(output, Architecture_amd64)
    parse_file(input, d)
    d.finish_file()

with open("../../s2n-bignum/x86/curve25519/curve25519_x25519base.S") as input, open(
    "../curve25519/src/low/x86_64/curve25519_x25519base.rs", "w"
) as output:
    d = Driver(output, Architecture_amd64)
    d.add_const_symbol('curve25519_x25519base_edwards25519_0g')
    d.add_const_symbol('curve25519_x25519base_edwards25519_8g')
    d.add_const_symbol('curve25519_x25519base_edwards25519_gtable')
    parse_file(input, d)
    d.finish_file()
