"""Lexer + recursive-descent parser for the JOCKY forensic language.

Grammar (case-insensitive keywords, '#' comments):

  program := rule+
  rule    := [RULE id [string]] meta* SCAN target [WHERE expr] REPORT [SEVERITY] sev meta*
  meta    := CLASS string | ATTACK string {"," string} | EXPLAIN string
  expr    := and_e {OR and_e} ;  and_e := not_e {AND not_e}
  not_e   := NOT not_e | '(' expr ')' | cmp
  cmp     := field op value | field IN '[' value {',' value} ']'
  op      := '=' | '!=' | '>' | '>=' | '<' | '<=' | '~' (contains) | MATCHES (regex)
"""
import re

KEYWORDS = {"RULE", "SCAN", "WHERE", "AND", "OR", "NOT", "REPORT", "SEVERITY",
            "CLASS", "ATTACK", "EXPLAIN", "IN", "MATCHES", "TRUE", "FALSE"}


class JockyError(Exception):
    def __init__(self, msg, line=0, col=0, errors=None):
        self.line, self.col = line, col
        self.errors = errors or [f"line {line}:{col}: {msg}" if line else msg]
        super().__init__("\n".join(self.errors))


_TOKEN = re.compile(r'''
  (?P<WS>[ \t\r]+)|(?P<NL>\n)|(?P<COMMENT>\#[^\n]*)
 |(?P<STRING>"(?:[^"\\\n]|\\.)*")
 |(?P<NUMBER>-?\d+(?:\.\d+)?)
 |(?P<OP>!=|>=|<=|=|>|<|~)
 |(?P<LB>\[)|(?P<RB>\])|(?P<LP>\()|(?P<RP>\))|(?P<COMMA>,)
 |(?P<IDENT>[A-Za-z_][A-Za-z0-9_\-\.]*)
''', re.X)


def tokenize(src):
    toks, line, ls, pos = [], 1, 0, 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            raise JockyError(f"unexpected character {src[pos]!r}", line, pos - ls + 1)
        kind, text, col = m.lastgroup, m.group(), pos - ls + 1
        pos = m.end()
        if kind == "NL":
            line += 1; ls = pos
        elif kind in ("WS", "COMMENT"):
            continue
        elif kind == "STRING":
            toks.append(("STRING", re.sub(r'\\(["\\])', r'\1', text[1:-1]), line, col))
        elif kind == "NUMBER":
            toks.append(("NUMBER", float(text) if "." in text else int(text), line, col))
        elif kind == "IDENT":
            up = text.upper()
            toks.append((up, text, line, col) if up in KEYWORDS else ("IDENT", text, line, col))
        else:
            toks.append((kind, text, line, col))
    toks.append(("EOF", "", line, 1))
    return toks


class Parser:
    def __init__(self, src):
        self.t, self.i, self.auto = tokenize(src), 0, 0

    def peek(self): return self.t[self.i]
    def next(self): tok = self.t[self.i]; self.i += 1; return tok

    def expect(self, kind, what=None):
        tok = self.next()
        if tok[0] != kind:
            raise JockyError(f"expected {what or kind}, found {tok[1] or 'end of file'!r}", tok[2], tok[3])
        return tok

    def program(self):
        rules = []
        while self.peek()[0] != "EOF":
            rules.append(self.rule())
        if not rules:
            raise JockyError("no rules found")
        return rules

    def meta(self, r):
        while self.peek()[0] in ("CLASS", "ATTACK", "EXPLAIN"):
            k = self.next()[0]
            if k == "CLASS": r["class"] = self.expect("STRING", "a string")[1]
            elif k == "EXPLAIN": r["explain"] = self.expect("STRING", "a string")[1]
            else:
                r["attack"].append(self.expect("STRING", "a technique id")[1])
                while self.peek()[0] == "COMMA":
                    self.next(); r["attack"].append(self.expect("STRING", "a technique id")[1])

    def rule(self):
        r = {"id": None, "name": "", "attack": [], "class": None, "explain": None, "where": None}
        tok = self.peek()
        r["line"] = tok[2]
        if tok[0] == "RULE":
            self.next()
            r["id"] = self.expect("IDENT", "a rule id")[1]
            if self.peek()[0] == "STRING": r["name"] = self.next()[1]
        self.meta(r)
        scan = self.expect("SCAN", "SCAN")
        r["line"] = r["line"] if tok[0] == "RULE" else scan[2]
        tgt = self.expect("IDENT", "a target (PROCESS, FILE, NETWORK, ...)")
        r["target"], r["target_pos"] = tgt[1].upper(), (tgt[2], tgt[3])
        if self.peek()[0] == "WHERE":
            self.next(); r["where"] = self.or_e()
        self.meta(r)
        self.expect("REPORT", "REPORT")
        if self.peek()[0] == "SEVERITY": self.next()
        sev = self.expect("IDENT", "a severity (LOW/MEDIUM/HIGH/CRITICAL)")
        r["severity"], r["severity_pos"] = sev[1].upper(), (sev[2], sev[3])
        self.meta(r)
        if r["id"] is None:
            self.auto += 1; r["id"] = f"ADHOC-{self.auto:03d}"
        return r

    def or_e(self):
        parts = [self.and_e()]
        while self.peek()[0] == "OR": self.next(); parts.append(self.and_e())
        return parts[0] if len(parts) == 1 else {"op": "or", "args": parts}

    def and_e(self):
        parts = [self.not_e()]
        while self.peek()[0] == "AND": self.next(); parts.append(self.not_e())
        return parts[0] if len(parts) == 1 else {"op": "and", "args": parts}

    def not_e(self):
        if self.peek()[0] == "NOT": self.next(); return {"op": "not", "arg": self.not_e()}
        if self.peek()[0] == "LP":
            self.next(); e = self.or_e(); self.expect("RP", "')'"); return e
        return self.cmp()

    def value(self):
        tok = self.next()
        if tok[0] in ("STRING", "NUMBER"): return tok[1]
        if tok[0] in ("TRUE", "FALSE"): return tok[0] == "TRUE"
        raise JockyError(f"expected a value, found {tok[1] or 'end of file'!r}", tok[2], tok[3])

    def cmp(self):
        f = self.expect("IDENT", "a field name")
        node = {"op": "cmp", "field": f[1].lower(), "pos": (f[2], f[3])}
        tok = self.next()
        if tok[0] == "IN":
            self.expect("LB", "'['")
            vals = [self.value()]
            while self.peek()[0] == "COMMA": self.next(); vals.append(self.value())
            self.expect("RB", "']'")
            node.update(cmp="in", value=vals)
        elif tok[0] == "MATCHES":
            node.update(cmp="matches", value=self.value())
        elif tok[0] == "OP":
            node.update(cmp={"=": "eq", "!=": "ne", ">": "gt", ">=": "ge", "<": "lt",
                             "<=": "le", "~": "contains"}[tok[1]], value=self.value())
        else:
            raise JockyError(f"expected a comparison operator after {f[1]!r}", tok[2], tok[3])
        return node


def parse(src):
    """Parse JOCKY source text into a list of raw rule ASTs."""
    return Parser(src).program()
