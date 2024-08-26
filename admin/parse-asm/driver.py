import string
from functools import reduce
import subprocess
from io import StringIO
import copy

from parse import Type, tokenise, is_comment


class Architecture:
    # registers (canonically named via `lookup_register`)
    # that should be ignored when calculating clobbers
    ignore_clobber = set()

    # constant references must be page aligned, because on aarch64
    # single-insn address loads have limited span at byte resolution
    # (but much wider at page resolution). this prevents relocation
    # errors in larger programs (where the emitted function is
    # >1MB away from the rodata section)
    #
    # this also converts `adr` insns of such references into `adrp`
    constant_references_must_be_page_aligned = False

    # instruction mnemonic for unconditional jump; used for hoisting
    unconditional_jump = "str"

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

    ignore_clobber = set("rbx rsp rbp rip".split())

    unconditional_jump = "jmp"

    @staticmethod
    def lookup_register(reg):
        for c in "ax bx cx dx si di ip".split():
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


class Architecture_aarch64(Architecture):
    """
    AArch64	reg	x[0-30]	r
    AArch64	vreg	v[0-31]	w
    AArch64	vreg_low16	v[0-15]	x
    AArch64	preg	p[0-15], ffr	Only clobbers
    ARM (ARM/Thumb2)	reg	r[0-12], r14	r
    ARM (Thumb1)	reg	r[0-7]	r
    ARM	sreg	s[0-31]	t
    ARM	sreg_low16	s[0-15]	x
    ARM	dreg	d[0-31]	w
    ARM	dreg_low16	d[0-15]	t
    ARM	dreg_low8	d[0-8]	x
    ARM	qreg	q[0-15]	w
    ARM	qreg_low8	q[0-7]	t
    ARM	qreg_low4	q[0-3]	x
    """

    ignore_clobber = set(["x19", "x29"])

    unconditional_jump = "b"

    constant_references_must_be_page_aligned = True

    @staticmethod
    def lookup_register(reg):
        for n in range(31):
            n = str(n)
            if reg in ["r" + n, "x" + n, "w" + n]:
                return "x" + n

        for n in range(32):
            n = str(n)
            if reg in ["v" + n, "q" + n, "d" + n, "s" + n, "h" + n]:
                return "v" + n

        for n in range(16):
            n = str(n)
            if reg == "p" + n:
                return reg


class Dispatcher:
    def __call__(self, ty, *args):
        func = getattr(self, "on_" + ty.lower())
        func(*args)

    def on_comment(self, comment):
        pass

    def on_vertical_whitespace(self):
        pass

    def on_align(self, contexts, alignment):
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

    def on_const(self, contexts, type, value):
        print("!!! UNHANDLED: on_const(", contexts, ",", type, ",", value, ")")

    def on_directive(self, contexts, directive, *args):
        print("!!! UNHANDLED on_directive(", contexts, ",", directive, ",", args, ")")

    def on_eof(self):
        pass


class QuietDispatcher(Dispatcher):
    def on_define(self, name, *value):
        pass

    def on_function(self, contexts, name):
        pass

    def on_asm(self, contexts, opcode, operands):
        pass

    def on_macro(self, name, operands):
        pass

    def on_label(self, contexts, label):
        pass

    def on_const(self, contexts, type, value):
        pass

    def on_directive(self, contexts, directive, *args):
        pass

    def on_eof(self):
        pass


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, ty, *args):
        self.events.append(copy.deepcopy((ty, args)))

    def replay(self, other):
        for ty, args in self.events:
            other(ty, *args)


class LabelCollector(QuietDispatcher):
    def __init__(self):
        self.labels = set()

    def on_label(self, contexts, label):
        if label in self.labels:
            print("duplicate label", label)
        self.labels.add(label)

    def get_labels(self):
        return set(self.labels)


class ConstantArray:
    def __init__(self, name):
        self.name = name
        self.type = None
        self.items = []
        self.lines = []

    def add_comment(self, comment):
        self.lines.append("// " + comment)

    def add_vertical_whitespace(self):
        self.lines.append("")

    def add_item(self, value):
        for v in tokenise(value):
            if v == ",":
                continue
            self.lines.append(v + ",")
            self.items.append(v)

    def set_type(self, type):
        if self.type is not None and self.type != type:
            raise ValueError("type varied within constant array")

        self.type = type


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
        elif cur in "[(.":
            collected.append(cur)
        else:
            collected.append(cur)
            collected.append(" ")

    if collected:
        yield '"' + "".join(collected) + '"'


def tokens_to_single_glued_string(tokens):
    return " ".join(tokens_to_quoted_spans(tokens))


def tokens_to_single_glued_string_lines(tokens, indent):
    tokens = list(tokens)
    if ";" in tokens:
        # if we have semicolons, assume they can be used
        # to improve formatting: they should terminate lines
        return _tokens_to_single_glued_string_semicolon_lines(tokens, indent)

    lines = []
    for span in tokens_to_quoted_spans(tokens):
        lines.append((" " * indent) + span)
    return "\n".join(lines)


def _tokens_to_single_glued_string_semicolon_lines(tokens, indent):
    lines = []
    collect = []
    for span in tokens_to_quoted_spans(tokens):
        if span.endswith(';"'):
            collect.append(span)
            lines.append((" " * indent) + " ".join(collect))
            collect = []
        else:
            collect.append(span)
    if collect:
        lines.append((" " * indent) + " ".join(collect))
    return "\n".join(lines)


def tokens_to_quoted_asm(tokens):
    return " ".join(tokens_to_quoted_spans(tokens))


def tokens_to_arg(tokens):
    def gen(tokens):
        tokens = list(tokens)
        for t in tokens:
            if isinstance(t, unquote):
                yield t.v
            elif t == ",":
                continue
            else:
                yield '"' + t + '"'

    g = list(gen(tokens))
    if len(g) == 0:
        return ""
    if len(g) == 1:
        return g[0]
    else:
        return "Q!(" + (" ".join(g)) + ")"


class FunctionState:
    def __init__(self, old_output):
        self.old_output = old_output
        self.macros_inside_function = StringIO()
        self.spool = StringIO()
        self.skip = False
        self.return_value = None
        self.parameter_map = []
        self.clobbers = set()
        self.labels = {}
        self.labels_defined = set()
        self.referenced_constant_syms = set()
        self.hoist = None
        self.hoisting = False
        self.past_hoist_end_marker = False

    def output(self):
        return self.spool

    def emit_ret(self):
        # we want rets in local functions during a hoist, but not at the end of
        # the primary function (leaving rustc to provider the function epilogue)
        if self.hoist is not None:
            return self.hoisting and self.hoist_mode_is_proc()
        else:
            return False

    def hoist_mode_is_proc(self):
        return self.hoist[0] == "proc"

    def hoist_last_label(self):
        return self.hoist[1]

    def hoist_finish_opcode(self):
        return self.hoist[2]

    def finishes_hoist(self, opcode, operands):
        return (
            self.hoisting
            and self.past_hoist_end_marker
            and opcode == self.hoist_finish_opcode()
        )


class RustDriver:
    def __init__(self, output, architecture):
        super(RustDriver, self).__init__()
        self.collector = Collector()
        self.label_pass = LabelCollector()
        self.formatter = RustFormatter(output, architecture)

    def discard_rust_function(self, function):
        self.formatter.discard_rust_function(function)

    def emit_rust_function(
        self,
        name,
        parameter_map,
        rust_decl,
        return_value=None,
        assertions=[],
        allow_inline=True,
        hoist=None,
    ):
        self.formatter.emit_rust_function(
            name,
            parameter_map,
            rust_decl,
            return_value=return_value,
            assertions=assertions,
            allow_inline=allow_inline,
            hoist=hoist,
        )

    def add_const_symbol(self, sym, rename=None, align=None):
        self.formatter.add_const_symbol(sym, rename=rename, align=align)

    def set_att_syntax(self, att_syntax):
        self.formatter.set_att_syntax(att_syntax)

    def __call__(self, ty, *args):
        self.collector(ty, *args)

        if ty == Type.EOF:
            self.finish()

    def finish(self):
        # we do a pass to determine which labels are defined,
        # because otherwise it is hard to know which tokens
        # refer to a later label
        self.collector.replay(self.label_pass)
        self.formatter.expected_labels = self.label_pass.get_labels()
        self.collector.replay(self.formatter)


class RustFormatter(Dispatcher):
    def __init__(self, output, architecture):
        super(RustFormatter, self).__init__()
        self.output = output
        self.arch = architecture
        self.rust_macros = {}
        self.expected_functions = {}
        self.constant_syms = set()
        self.constant_sym_alignment = {}
        self.constant_sym_rename = {}
        self.current_constant_array = None
        self.emitted_page_aligned_types = set()
        self.function_state = None
        self.expected_labels = []
        self.att_syntax = False
        self.start()

    def discard_rust_function(self, function):
        self.expected_functions[function] = None

    def emit_rust_function(
        self,
        name,
        parameter_map,
        rust_decl,
        return_value=None,
        assertions=[],
        allow_inline=True,
        hoist=None,
    ):
        self.expected_functions[name] = (
            parameter_map,
            rust_decl,
            return_value,
            allow_inline,
            hoist,
            assertions,
        )

    def set_att_syntax(self, att_syntax):
        self.att_syntax = att_syntax

    def start(self):
        print(
            """
#![allow(
    non_upper_case_globals,
    unused_macros,
    unused_imports,
)]
use crate::low::macros::*;

""",
            file=self.output,
        )

    def add_const_symbol(self, sym, rename=None, align=None):
        self.constant_syms.add(sym)
        name = rename if rename else sym
        self.constant_sym_rename[sym] = name
        self.constant_sym_alignment[name] = align

    def find_label(self, label, defn=False):
        """
        Returns an ordinal "local label" for the name `label`

        Returns (ordinal, defined_before).

        `defined_before` is true if the label is already defined.
        """
        func = self.function_state
        if func is None:
            return 0, True

        if defn:
            func.labels_defined.add(label)

        id = func.labels.get(label, None)
        if id is not None:
            return id, label in func.labels_defined

        # workaround warning that numeric labels must not solely
        # consist of '1' and '0' characters. unhinged!
        next_id = max(func.labels.values()) + 1 if func.labels else 1
        while len(str(next_id).replace("1", "").replace("0", "")) == 0:
            next_id += 1

        func.labels[label] = next_id
        return next_id, label in func.labels_defined

    def looks_like_label(self, label):
        return label in self.expected_labels

    def register_rust_macro(self, name, value, params=None):
        self.rust_macros[name] = (value, params)

    def contains_constant_ref(self, *values):
        for v in values:
            for t in tokenise(v):
                if t in self.constant_syms:
                    return True

    def expand_rust_macros(self, *values, params={}):
        for v in values:
            for t in tokenise(v):
                if t in params:
                    yield unquote("$" + t)
                elif t in self.rust_macros:
                    macro_value, macro_args = self.rust_macros[t]
                    for vv in macro_value:
                        self.visit_operands(vv)
                    # this code path is for macro expansions that don't
                    # "look like function calls", macros mentioned like that
                    # must not have any arguments
                    assert macro_args == None
                    yield unquote("%s!()" % t)
                elif is_comment(t):
                    yield unquote(t)
                elif t in self.constant_syms:
                    t = self.constant_sym_rename[t]
                    if self.function_state:
                        self.function_state.referenced_constant_syms.add(t)
                    if self.arch.constant_references_must_be_page_aligned:
                        yield unquote('PageRef!("' + t + '")')
                    else:
                        yield "{" + t + "}"
                elif (
                    self.function_state and t in self.function_state.labels
                ) or self.looks_like_label(t):
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
        assert len(values) == 1
        value = values[0]
        args = value.split(",")
        args = [a.strip() for a in args]
        return ", ".join(tokens_to_arg(self.expand_rust_macros(a)) for a in args)

    def on_function(self, contexts, name):
        assert contexts == []
        if name in self.expected_functions:
            defn = self.expected_functions[name]

            self.function_state = FunctionState(self.output)
            self.output = self.function_state.output()

            if defn is None:
                self.function_state.skip = True
            else:
                (
                    parameter_map,
                    rust_decl,
                    return_value,
                    allow_inline,
                    hoist,
                    assertions,
                ) = defn
                self.function_state.parameter_map = parameter_map
                self.function_state.rust_decl = rust_decl
                self.function_state.return_value = return_value
                self.function_state.hoist = hoist

            if not self.function_state.skip:
                locals = ""
                if self.function_state.return_value:
                    rtype, rname, _ = self.function_state.return_value
                    locals = "let %s: %s;" % (rname, rtype)
                for a in assertions:
                    locals += "debug_assert!(%s);" % a

                print("", file=self.output)

                if not allow_inline:
                    print("#[inline(never)]", file=self.output)

                print(
                    """%s {
                    %s
                    unsafe { core::arch::asm!(
                """
                    % (self.function_state.rust_decl, locals),
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
        if self.function_state:
            f = self.function_state.macros_inside_function
            print("// <macro definition %s hoisted upwards>" % name, file=self.output)
        else:
            f = self.output

        tokens = tokenise(name)
        if len(tokens) == 1:
            assert len(value) == 1
            self.register_rust_macro(tokens[0], value)
            value = self.expand_rust_macros_in_macro_decl(*value, indent=0)
            print(
                """macro_rules! %s { () => { Q!(%s) } }""" % (tokens[0], value),
                file=f,
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
                file=f,
            )

    def on_directive(self, contexts, directive, *args):
        if directive == ".byte" and list(args) == ["0xf3,0xc3"]:
            # this is "rep ret", obfuscated for some reason
            return self.finish_function()
        elif directive == ".byte" and self.function_state:
            # TODO: disassemble these for readability
            self.on_asm(contexts, directive, *args)
        elif directive == ".byte" and self.current_constant_array:
            # avoid binary marker leaking into operational constants
            if args and args[0].startswith("65,69,83,45,78,73,32,71,67,77,32,109"):
                return
            self.on_const(contexts, directive, *args)

    def on_asm(self, contexts, opcode, operands):
        if "WINDOWS_ABI" in contexts:
            # No need for these as we leave function entry/return to rustc
            return

        if opcode in ("ret", "retl") and (
            (self.function_state and not self.function_state.emit_ret())
            or not self.function_state
        ):
            return self.finish_function()

        self.visit_operands(operands)

        contains_constant_ref = self.contains_constant_ref(operands)
        operands = self.expand_rust_macros_in_asm(operands)
        if operands:
            if (
                contains_constant_ref
                and self.arch.constant_references_must_be_page_aligned
                and opcode == "adr"
            ):
                opcode = "adrp"

        parts = ['"    %-15s "' % opcode]
        parts.append(operands)
        print("Q!(" + (" ".join(parts)) + "),", file=self.output)

        if self.function_state and self.function_state.finishes_hoist(opcode, operands):
            return self.finish_function()

    def visit_operands(self, operands):
        for t in tokenise(operands):
            t = t.lstrip("%")
            actual_reg = self.arch.lookup_register(t)
            if actual_reg and self.function_state:
                self.function_state.clobbers.add(actual_reg)

    def on_label(self, contexts, label):
        if "WINDOWS_ABI" in contexts:
            return

        if (
            self.function_state
            and self.function_state.hoisting
            and self.function_state.hoist_last_label() == label
        ):
            self.function_state.past_hoist_end_marker = True

        if label in self.expected_functions:
            self.on_function(contexts, label)
            return

        if label in self.constant_syms:
            self.finish_constant_array()
            self.start_constant_array(self.constant_sym_rename[label])
            return

        id, _ = self.find_label(label, defn=True)
        print('Q!(Label!("%s", %d) ":"),' % (label, id), file=self.output)

    def on_macro(self, name, params):
        assert name in self.rust_macros
        macro_value, _macro_args = self.rust_macros[name]
        for vv in macro_value:
            self.visit_operands(vv)
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
                ".byte": "u8",
                ".quad": "u64",
                ".long": "u32",
            }[ca.type]

            array_type = "[%s; %d]" % (rust_type, len(ca.items))
            if (
                self.arch.constant_references_must_be_page_aligned
                or self.constant_sym_alignment[ca.name]
            ):
                if self.constant_sym_alignment[ca.name]:
                    alignment = self.constant_sym_alignment[ca.name]
                    how = "B" + str(alignment)
                else:
                    alignment = 16384
                    how = "Page"

                rust_type = "%sAligned%sArray%d" % (how, rust_type, len(ca.items))
                value_start = rust_type + "("
                value_end = ")"

                if rust_type not in self.emitted_page_aligned_types:
                    print("#[allow(dead_code)]", file=self.output)
                    print("#[repr(align(%d))]" % alignment, file=self.output)
                    print(
                        "struct %s(%s);\n" % (rust_type, array_type), file=self.output
                    )
                    self.emitted_page_aligned_types.add(rust_type)
            else:
                rust_type = array_type
                value_start = ""
                value_end = ""

            print(
                "static %s: %s = %s[" % (ca.name, rust_type, value_start),
                file=self.output,
            )
            for line in ca.lines:
                print("    %s" % line, file=self.output)
            print("]%s;" % value_end, file=self.output)
            print("", file=self.output)

    def finish_function(self):
        if self.function_state is None:
            return

        if self.function_state.hoist and not self.function_state.hoisting:
            mode, after, fin = self.function_state.hoist
            # linear hoisting: multiple rets from the main function, no calls, only jmps
            #                  all rets are replaced with jmps to hoist_finish
            # proc hoisting: single ret from the main function, but local functions after
            #                that.  first ret is replaced with a jmp, others are left.
            #
            # this is deeply manual and inflexible.
            #
            # TODO: do a basic block pass, to determine which blocks are reached from the
            # main function, and how (call/jmp), and then simply emit the correct code.
            assert mode in ("linear", "proc")
            print(
                "// %s hoisting in -> %s after %s" % (mode, fin, after),
                file=self.output,
            )
            self.expected_labels.add("hoist_finish")
            self.on_asm([], self.arch.unconditional_jump, "hoist_finish")
            self.function_state.hoisting = True
            return
        elif self.function_state.hoisting and self.function_state.past_hoist_end_marker:
            self.on_label([], "hoist_finish")
            self.function_state.hoisting = False
        elif (
            self.function_state.hoisting
            and not self.function_state.hoist_mode_is_proc()
        ):
            self.on_asm([], self.arch.unconditional_jump, "hoist_finish")
            return

        for dir, reg, param in self.function_state.parameter_map:
            print('%s("%s") %s,' % (dir, reg, param), file=self.output)

        for c in sorted(self.function_state.referenced_constant_syms):
            print("%s = sym %s," % (c, c), file=self.output)

        print("// clobbers", file=self.output)
        for c in sorted(self.function_state.clobbers):
            if c in [x[1] for x in self.function_state.parameter_map]:
                continue
            if c in self.arch.ignore_clobber:
                continue
            print('out("%s") _,' % c, file=self.output)
        if self.att_syntax:
            print("options(att_syntax),", file=self.output)
        print("    )};", file=self.output)

        if self.function_state.return_value:
            _, rname, rexpr = self.function_state.return_value
            print("    %s" % rexpr, file=self.output)

        print("}", file=self.output)

        # finally, restore original output and emit macros before
        # function body
        self.output = self.function_state.old_output
        if not self.function_state.skip:
            self.output.write(self.function_state.macros_inside_function.getvalue())
            self.output.write(self.function_state.output().getvalue())
        self.function_state = None

    def on_eof(self):
        self.finish_constant_array()

        filename = self.output.name
        self.output.close()

        subprocess.check_call(["rustfmt", filename])
        print("GENERATED", filename)


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

    tt = tokenise("mov     v9.d[0], xzr")
    print(repr(tt))
    assert tokens_to_quoted_asm(tt) == '"mov v9.d[0], xzr"'

    tt = tokenise("add     v22.2s, v2.2s, v3.2s")
    print(repr(tt))
    assert tokens_to_quoted_asm(tt) == '"add v22.2s, v2.2s, v3.2s"'

    print(tokens_to_quoted_asm(tokenise("b.ne    curve25519_x25519_invloop")))
    assert (
        tokens_to_quoted_asm(tokenise("b.ne    curve25519_x25519_invloop"))
        == '"b.ne curve25519_x25519_invloop"'
    )
    assert (
        tokens_to_quoted_asm(tokenise("mov    [P0+0x18], r11"))
        == '"mov [P0 + 0x18], r11"'
    )

    print(repr(tokenise("stp     x2, x3, [xn+16]")))

    assert tokenise("x0, x1, [xn]") == ["x0", ",", "x1", ",", "[", "xn", "]"]
    assert tokenise("ldr x0, /* inside comment */ 5") == [
        "ldr",
        "x0",
        ",",
        "/* inside comment */",
        "5",
    ]
    print(tokenise("movbig( n0, #0xf3b9, #0xcac2, #0xfc63, #0x2551)"))
    assert tokenise(".Lloop_ssse3:") == [".Lloop_ssse3", ":"]
