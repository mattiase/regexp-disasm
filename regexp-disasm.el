;;; regexp-disasm -- disassemble regexp bytecode  -*- lexical-binding: t -*-

;; Author: Mattias Engdegård <mattiase@acm.org>
;; Version: 1.0
;; Package-Requires: ((emacs "26.1"))
;; URL: https://github.com/mattiase/regexp-disasm

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; Disassemble compiled Emacs regexp bytecode.
;; This code requires Emacs to have been compiled with the
;; regexp-bytecode patch!
;;
;; Effective use of this code requires some knowledge of the internals
;; of the regexp engine.  See re_opcode_t in regex-emacs.c, as well as
;; most of the rest of that file.

(defconst regexp-disasm--classes
  [word lower punct space upper multibyte alpha alnum graph print blank]
  "Vector of character classes, corresponding to BIT_* in regex-emacs.c.
The vector index corresponds to the bit number.")

(defconst regexp-disasm--syntax-codes
  [whitespace punctuation word symbol
   open-parenthesis close-parenthesis expression-prefix string-quote
   paired-delimiter escape character-quote comment-start comment-end
   inherit comment-delimiter string-delimiter]
  "Vector of syntax codes, corresponding to enum syntaxcode in syntax.h.
The vector index is the enum value; the symbol names are from `rx'.")

(defun regexp-disasm--decode-multibyte (bytes)
  "Decode BYTES from the internal string format to the string it represents."
  ;; Each raw byte in the 80..ff range is internally represented as the
  ;; two bytes 1100000x 10xxxxxx, which are decoded as separate raw bytes
  ;; by utf-8-emacs, so we have to post-process the results.
  (let* ((s (decode-coding-string bytes 'utf-8-emacs))
         (len (length s))
         (i 0)
         (start 0)
         (parts nil))
    (while (< i (1- len))
      (if (and (<= #x3fffc0 (aref s i) #x3fffc1)
               (<= #x3fff80 (aref s (1+ i)) #x3fffbf))
          ;; A pair of chars representing a raw byte.
          (progn
            (when (> i start)
              (push (substring s start i) parts))
            (push (string (+ #x3fff80
                             (ash (logand (aref s i) 1) 6)
                             (logand (aref s (1+ i)) #x3f)))
                  parts)
            (setq start (+ i 2))
            (setq i start))
        (setq i (1+ i))))
    (when (> len start)
      (push (substring s start) parts))
    (apply #'concat (nreverse parts))))

;;;###autoload
(defun regexp-disasm (regexp &optional case-table)
  "Disassemble the bytecode for REGEXP; return list of instructions.
CASE-TABLE, if non-nil, is a translation table for case-folding.
Instructions take the form (ADDRESS . INSTR) where ADDRESS is the
byte offset and INSTR an S-expression representing the instruction."
  (let* ((bc (regexp-bytecode regexp case-table))
         (read-u16 (lambda (ofs) (+ (aref bc ofs)
                                    (ash (aref bc (1+ ofs)) 8))))
         (read-u24 (lambda (ofs) (+ (aref bc ofs)
                                    (ash (aref bc (+ ofs 1)) 8)
                                    (ash (aref bc (+ ofs 2)) 16))))
         (read-s16 (lambda (ofs) (let ((x (funcall read-u16 ofs)))
                                   (- x (ash (logand x #x8000) 1)))))
         (len (length bc))
         (i 0)
         (entries nil))
    (while (< i len)
      ;; This code depends on the exact details of the regexp bytecode
      ;; representation; see re_opcode_t in regex-emacs.c.
      (let* ((opcode (aref bc i))
             (entry-and-size
               (pcase opcode
                 (0 '(no-op . 1))
                 (1 '(succeed . 1))
                 (2 (let* ((nbytes (aref bc (1+ i)))
                           (raw (substring bc (+ i 2) (+ i 2 nbytes)))
                           ;; Exact strings are multibyte-coded iff the
                           ;; original regexp is.
                           (str (if (multibyte-string-p regexp)
                                    (regexp-disasm--decode-multibyte raw)
                                  raw)))
                      (cons (list 'exact str) (+ 2 nbytes))))
                 (3 '(not-newline . 1))        ; `anychar' is a misnomer
                 ((or 4 5)              ; `charset', `charset-not'
                  (let* ((negated (= opcode 5))
                         (bitmap-len-raw (aref bc (1+ i)))
                         (bitmap-len (logand bitmap-len-raw #x7f))
                         (have-range-table (/= (logand bitmap-len-raw #x80) 0))
                         (npairs (if have-range-table
                                     (funcall read-u16 (+ i 2 bitmap-len 2))
                                   0))
                         (bitmap-pairs nil)
                         (classes nil)
                         (pairs nil))

                    ;; Convert the bitmap to ranges.
                    (let ((first nil))
                      (dotimes (j (* bitmap-len 8))
                        (if (/= (logand (aref bc (+ i 2 (ash j -3)))
                                        (ash 1 (logand j 7)))
                                0)
                            (unless first
                              (setq first j))
                          (when first
                            (push (cons first (1- j)) bitmap-pairs)
                            (setq first nil))))
                      (when first
                        (push (cons first (1- (* bitmap-len 8))) bitmap-pairs)))

                    (when have-range-table
                      ;; Convert class bits to list of classes.
                      (let ((class-bits (funcall read-u16 (+ i 2 bitmap-len))))
                        (dotimes (j (length regexp-disasm--classes))
                          (when (/= (logand class-bits (ash 1 j)) 0)
                            (push (aref regexp-disasm--classes j) classes))))

                      ;; Read range table.
                      (dotimes (j npairs)
                        (let* ((ofs (+ i 2 bitmap-len 4 (* j 6)))
                               (from (funcall read-u24 ofs))
                               (to   (funcall read-u24 (+ ofs 3))))
                          (push (cons from to) pairs))))

                    (cons (list (if negated 'charset-not 'charset)
                                (nreverse bitmap-pairs)
                                (nreverse classes)
                                (nreverse pairs))
                          (+ 2 bitmap-len
                             (if have-range-table 4 0) (* npairs 6)))))
                 (6 (cons (list 'start-memory (aref bc (1+ i)))
                          2))
                 (7 (cons (list 'stop-memory (aref bc (1+ i)))
                          2))
                 (8 (cons (list 'duplicate (aref bc (1+ i)))
                          2))
                 (9 '(begline . 1))
                 (10 '(endline . 1))
                 (11 '(begbuf . 1))
                 (12 '(endbuf . 1))
                 (13 (cons (list 'jump
                                 (+ (funcall read-s16 (1+ i)) i 3))
                           3))
                 (14 (cons (list 'on-failure-jump
                                 (+ (funcall read-s16 (1+ i)) i 3))
                           3))
                 (15 (cons (list 'on-failure-keep-string-jump
                                 (+ (funcall read-s16 (1+ i)) i 3))
                           3))
                 (16 (cons (list 'on-failure-jump-loop
                                 (+ (funcall read-s16 (1+ i)) i 3))
                           3))
                 (17 (cons (list 'on-failure-jump-nastyloop
                                 (+ (funcall read-s16 (1+ i)) i 3))
                           3))
                 (18 (cons (list 'on-failure-jump-smart
                                 (+ (funcall read-s16 (1+ i)) i 3))
                           3))
                 (19 (cons (list 'succeed-n
                                 (+ (funcall read-s16 (1+ i)) i 3)
                                 (funcall read-u16 (+ i 3)))
                           5))
                 (20 (cons (list 'jump-n
                                 (+ (funcall read-s16 (1+ i)) i 3)
                                 (funcall read-u16 (+ i 3)))
                           5))
                 (21 (cons (list 'set-number-at
                                 (+ (funcall read-s16 (1+ i)) i 3)
                                 (funcall read-u16 (+ i 3)))
                           5))
                 (22 '(wordbeg . 1))
                 (23 '(wordend . 1))
                 (24 '(wordbound . 1))
                 (25 '(notwordbound . 1))
                 (26 '(symbeg . 1))
                 (27 '(symend . 1))
                 ;; Use symbolic names for syntax classes.
                 (28 (cons (list 'syntaxspec
                                 (aref regexp-disasm--syntax-codes
                                       (aref bc (1+ i))))
                           2))
                 (29 (cons (list 'notsyntaxspec
                                 (aref regexp-disasm--syntax-codes
                                       (aref bc (1+ i))))
                           2))
                 (30 '(at-dot . 1))
                 ;; Use the category code char for categories.
                 (31 (cons (list 'categoryspec (aref bc (1+ i)))
                           2))
                 (32 (cons (list 'notcategoryspec (aref bc (1+ i)))
                           2))
                 (_ (error "bad opcode at offset %d: 0x%02x" i opcode))))
             (entry (car entry-and-size))
             (size (cdr entry-and-size)))
        (push (cons i entry) entries)
        (setq i (+ i size))))
    (nreverse entries)))

;;;###autoload
(defun regexp-disassemble (regexp &optional case-table)
  "Print the disassembled bytecode for REGEXP.
If CASE-TABLE is non-nil, use it as translation table for case-folding.

Cached bytecode is returned if available.  Since a compiled regexp can
be modified when it is used in matching, the exact output of this function
may vary, but it should be operationally equivalent."
  (interactive "XRegexp (Lisp expression): ")
  (let* ((instructions (regexp-disasm regexp case-table))
         (control-chars '((?\b . ?b)
                          (?\t . ?t)
                          (?\n . ?n)
                          (?\v . ?v)
                          (?\f . ?f)
                          (?\r . ?r)
                          (?\e . ?e)))
         (quote-byte (lambda (c)
                       (let ((esc (assq c control-chars)))
                         (cond (esc (string ?\\ (cdr esc)))
                               ((memq c '(?\\ ?\")) (string ?\\ c))
                               ((or (<= c 31) (<= #x7f c #xff))
                                (format "\\%03o" c))
                               (t (string c))))))
         (quote-string-char (lambda (c)
                              (let ((esc (assq c control-chars)))
                                (cond (esc (string ?\\ (cdr esc)))
                                      ((memq c '(?\\ ?\"))
                                       (string ?\\ c))
                                      ((or (<= c 31) (= c 127)
                                           (>= c #x3fff80))
                                       (format "\\%03o" (logand c #xff)))
                                      (t (string c))))))
         (quote-string (lambda (s)
                         (concat "\""
                                 (mapconcat quote-string-char
                                            ;; Make multibyte, to distinguish
                                            ;; raw chars from U+0080..00ff.
                                            (string-to-multibyte s)
                                            "")
                                 "\"")))
         (quote-range (lambda (range quote-char)
                        (if (eq (car range) (cdr range))
                            (funcall quote-char (car range))
                          (format "%s-%s"
                                  (funcall quote-char (car range))
                                  (funcall quote-char (cdr range))))))
         (quote-range-uni
          (lambda (range) (funcall quote-range range quote-byte)))
         (quote-range-multi
          (lambda (range) (funcall quote-range range #'string))))
    (with-output-to-temp-buffer "*Regexp-disassemble*"
      (with-current-buffer standard-output
        (insert (format "Disassembly of regexp %s\n\n"
                        (funcall quote-string regexp)))
        (dolist (instr instructions)
          (let* ((addr (car instr))
                 (op (cdr instr))
                 (line
                  (pcase op
                    ((pred symbolp) (symbol-name op))
                    (`(exact ,s) (format "exact %s" (funcall quote-string s)))
                    (`(,(or 'charset 'charset-not)
                       ,bitmap-pairs ,classes ,pairs)
                     ;; FIXME: Maybe use a less ambiguous charset syntax.
                     ;; Avoid ranges when endpoints are adjacent.
                     ;; What to do about metachars like `]' and `-'?
                     (concat (format "%s [%s]"
                                     (car op)
                                     (mapconcat quote-range-uni
                                                bitmap-pairs ""))
                             (and classes
                                  (concat " [:"
                                          (mapconcat
                                           #'symbol-name classes ",")
                                          ":]"))
                             (and pairs
                                  (concat " ["
                                          (mapconcat quote-range-multi pairs "")
                                          "]"))))
                    (`(,(or 'start-memory 'stop-memory 'duplicate) ,n)
                     (format "%s group %d" (car op) n))
                    (`(,(or 'jump 'on-failure-jump 'on-failure-keep-string-jump
                            'on-failure-jump-loop 'on-failure-jump-nastyloop
                            'on-failure-jump-smart)
                       ,dest)
                     (format "%s to %d" (car op) dest))
                    (`(,(or 'succeed-n 'jump-n) ,dest ,val)
                     (format "%s to %d, value %d" (car op) dest val))
                    (`(set-number-at ,dest ,val)
                     ;; We adjust the destination address so that it
                     ;; refers to the instruction, not to the offset
                     ;; of the number.
                     (format "%s instr %d to value %d" (car op) (- dest 3) val))
                    (`(,(or 'syntaxspec 'notsyntaxspec) ,syn)
                     (format "%s %s" (car op) syn))
                    (`(,(or 'categoryspec 'notcategoryspec) ,ch)
                     (format "%s '%c'" (car op) ch))
                    (_ (error "unrecognised opcode: %S at %S" op addr)))))
            (insert (format "%5d  %s\n" addr line))))))))

(provide 'regexp-disasm)

;;; regexp-disasm.el ends here
