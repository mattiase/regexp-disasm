# regexp-disasm – Emacs regexp bytecode disassembler

regexp-disasm disassembles compiled Emacs regexp bytecode to something
that can (just) be understood by a human. It is mainly intended for
those debugging the Emacs regexp engine, but anyone curious about how
it works and how regexps are interpreted may find it interesting.

This is a specialised package: it requires some knowledge of the
regexp internals to be useful. See `src/regex-emacs.c` in the Emacs
source tree, and `re_opcode_t` in particular.

## Installation

**This package requires a patched Emacs.**
Apply `regexp-bytecode.patch` to your Emacs source tree and rebuild.
Start Emacs and load `regexp-disasm.el`.

## Usage

* `(regexp-disassemble REGEXP &optional CASE-TABLE)`

  Compile REGEXP with the optional CASE-TABLE and display a
  pretty-printed disassembly in a separate buffer.
  This function can be used as an interactive command; note that
  the regexp is then input as a Lisp expression, not a string.

* `(regexp-disasm REGEXP &optional CASE-TABLE)`

  Compile REGEXP with the optional CASE-TABLE and return the disassembly
  as a list of instructions. Each instruction takes the form
  `(ADDRESS . INSTR)` where ADDRESS is the byte offset and INSTR is the
  instruction in a symbolic form.

For both functions, previously compiled (cached) regexp bytecode may
be used. It should be functionally equivalent but may not be
identical, since Emacs regexps sometimes use self-modifying code.
