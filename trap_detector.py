import re
import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from variable_renamer import VariableRenamer


_SHORT_STRING_RE = re.compile(r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')', re.DOTALL)
_LONG_BRACKET_RE = re.compile(r'\[(=*)\[.*?\]\1\]', re.DOTALL)
_LINE_COMMENT_RE = re.compile(r'--.*?(?=\n|$)')
_LONG_COMMENT_RE = re.compile(r'--\[(=*)\[.*?\]\1\]', re.DOTALL)


@dataclass(frozen=True)
class NoOpEvidence:
    """Description of a statically-proven no-op construct."""

    kind: str
    name: Optional[str]
    snippet: str
    start: int
    end: int
    proof: Dict[str, Any]
    removable: bool = True

    def to_json(self) -> Dict[str, Any]:
        data = {
            "kind": self.kind,
            "name": self.name,
            "snippet": self.snippet.strip(),
            "proof": self.proof,
            "removable": self.removable,
        }
        return data

class TrapDetector:
    """Detects and removes anti-deobfuscation traps from Luraph/LuaMor obfuscated code."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._function_scanner: Optional[VariableRenamer] = None
        self.last_noop_report: List[NoOpEvidence] = []

        # Common trap patterns
        self.trap_patterns = {
            'pcall_traps': [
                r'pcall\s*\(\s*function\s*\(\s*\)\s*error\s*\(["\'].*?["\'].*?\)\s*end\s*\)',
                r'pcall\s*\(\s*loadstring\s*\(["\'].*?error.*?["\'].*?\)\s*\)',
                r'pcall\s*\(\s*function\s*\(\s*\)\s*while\s+true\s+do\s*end\s*end\s*\)',
            ],
            'xpcall_traps': [
                r'xpcall\s*\(\s*function\s*\(\s*\).*?error.*?end\s*,\s*function.*?\)',
                r'xpcall\s*\(\s*loadstring.*?,\s*function.*?\)',
            ],
            'fake_loadstring': [
                r'loadstring\s*\(["\'].*?syntax\s+error.*?["\'].*?\)',
                r'loadstring\s*\(["\'].*?attempt\s+to.*?["\'].*?\)',
                r'loadstring\s*\(["\'].*?\x00.*?["\'].*?\)',
            ],
            'dummy_functions': [
                r'local\s+function\s+\w+\s*\(\s*\)\s*end',
                r'function\s+\w+\s*\(\s*\)\s*return\s*end',
                r'function\s+\w+\s*\(\s*.*?\s*\)\s*return\s+.*?\s*end',
            ],
            'infinite_loops': [
                r'while\s+true\s+do\s*end',
                r'repeat\s*until\s+false',
                r'for\s+\w+\s*=\s*1\s*,\s*math\.huge\s+do.*?end',
            ],
            'debug_hooks': [
                r'debug\.sethook\s*\([^)]+\)',
                r'debug\.traceback\s*\([^)]*\)',
            ],
            'environment_checks': [
                r'getfenv\s*\(\s*\)\s*\[\s*["\'].*?["\'].*?\s*\]',
                r'_G\s*\[\s*["\'].*?["\'].*?\].*?==.*?nil',
                r'type\s*\(\s*.*?\s*\)\s*~=\s*["\']function["\']',
            ],
        }

        # Function wrappers that do nothing
        self.dummy_wrapper_patterns = [
            r'local\s+(\w+)\s*=\s*function\s*\(\s*([^)]*)\s*\)\s*return\s+([^()]+)\s*\(\s*\2\s*\)\s*end',
            r'function\s+(\w+)\s*\(\s*([^)]*)\s*\)\s*return\s+([^()]+)\s*\(\s*\2\s*\)\s*end',
        ]

    def detect_traps(self, code: str) -> Dict[str, List[str]]:
        """Detect all types of anti-deobfuscation traps in the code."""
        detected_traps = {}
        for trap_type, patterns in self.trap_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, code, re.IGNORECASE | re.DOTALL)
                matches.extend(found)
            if matches:
                detected_traps[trap_type] = matches
                self.logger.info(f"Detected {len(matches)} {trap_type}")
        return detected_traps

    def remove_traps(self, code: str) -> str:
        """Remove detected traps from the code."""
        cleaned_code = code
        for trap_type, patterns in self.trap_patterns.items():
            if trap_type in {"debug_hooks", "environment_checks", "dummy_functions"}:
                continue
            for pattern in patterns:
                cleaned_code = re.sub(pattern, '', cleaned_code, flags=re.IGNORECASE | re.DOTALL)
        cleaned_code = self._remove_dummy_wrappers(cleaned_code)
        # Cleanup empty lines
        cleaned_code = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned_code)
        cleaned_code = re.sub(r'^\s*\n', '', cleaned_code, flags=re.MULTILINE)
        return cleaned_code

    def _remove_dummy_wrappers(self, code: str) -> str:
        """Remove function wrappers that do nothing but obscure calls."""
        cleaned_code = code
        for pattern in self.dummy_wrapper_patterns:
            matches = re.finditer(pattern, cleaned_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                wrapper_name = match.group(1)
                actual_function = match.group(3)
                # Remove wrapper definition
                cleaned_code = cleaned_code.replace(match.group(0), '')
                # Replace all calls to wrapper with actual function calls
                wrapper_call_pattern = rf'\b{re.escape(wrapper_name)}\s*\('
                cleaned_code = re.sub(wrapper_call_pattern, f'{actual_function}(', cleaned_code)
        return cleaned_code

    def analyze_function_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze functions to identify likely dummy functions."""
        functions = re.findall(
            r'(?:local\s+)?function\s+(\w+)\s*\([^)]*\)(.*?)end',
            code, re.DOTALL | re.IGNORECASE
        )
        analysis = {
            'total_functions': len(functions),
            'likely_dummies': [],
            'complex_functions': [],
            'suspicious_functions': []
        }
        for func_name, func_body in functions:
            body_lines = [line.strip() for line in func_body.split('\n') if line.strip()]
            non_comment_lines = [line for line in body_lines if not line.startswith('--')]
            characteristics = {
                'name': func_name,
                'total_lines': len(body_lines),
                'code_lines': len(non_comment_lines),
                'has_return': 'return' in func_body.lower(),
                'has_loops': any(k in func_body.lower() for k in ['while', 'for', 'repeat']),
                'has_conditionals': any(k in func_body.lower() for k in ['if', 'elseif', 'else']),
                'calls_other_functions': len(re.findall(r'\w+\s*\(', func_body)) > 0
            }
            if characteristics['code_lines'] <= 1 and not characteristics['has_return']:
                analysis['likely_dummies'].append(characteristics)
            elif (characteristics['code_lines'] > 10 and
                  characteristics['has_loops'] and
                  characteristics['has_conditionals']):
                analysis['complex_functions'].append(characteristics)
            elif (characteristics['calls_other_functions'] and
                  not characteristics['has_loops'] and
                  not characteristics['has_conditionals']):
                analysis['suspicious_functions'].append(characteristics)
        return analysis

    # -- No-op detection -------------------------------------------------
    def detect_noop_insertions(self, code: str) -> List[NoOpEvidence]:
        """Return heuristically proven no-op helpers and junk loops."""

        helpers = self._detect_noop_helpers(code)
        loops = self._detect_noop_loops(code)
        return helpers + loops

    def _ensure_function_scanner(self) -> VariableRenamer:
        if self._function_scanner is None:
            self._function_scanner = VariableRenamer()
        return self._function_scanner

    def _strip_marked_noops(self, code: str, entries: List[NoOpEvidence]) -> str:
        removable = [entry for entry in entries if entry.removable]
        if not removable:
            return code
        pieces: List[str] = []
        last_index = 0
        for entry in sorted(removable, key=lambda item: item.start):
            pieces.append(code[last_index:entry.start])
            last_index = entry.end
        pieces.append(code[last_index:])
        return ''.join(pieces)

    def _detect_noop_helpers(self, code: str) -> List[NoOpEvidence]:
        scanner = self._ensure_function_scanner()
        spans = scanner._scan_functions(code)
        findings: List[NoOpEvidence] = []
        for span in spans:
            header = span.header
            if not header:
                continue
            name = header.name
            start_index = span.start
            if code[max(0, start_index - 6):start_index] == 'local ':
                start_index -= 6
            line_start, line_end = self._expand_to_line(code, start_index, span.end)
            body = code[header.end:span.end - 3]
            body_no_comments = self._remove_comments(body).strip()
            body_no_effects = self._strip_comments_and_strings(body).strip()
            classification: Optional[str]
            proof: Dict[str, Any]
            removable = False
            if not body_no_effects:
                classification = 'empty_helper'
                proof = {
                    'analysis': 'function body empty after removing comments and literals',
                    'call_count': self._count_identifier_calls(code, name, line_start, line_end) if name else 0,
                    'params': header.params,
                }
            else:
                return_expr = self._extract_simple_return(body_no_comments)
                if return_expr is None:
                    continue
                expr_kind, expr_value = return_expr
                proof = {
                    'analysis': 'single return statement with simple expression',
                    'expression': expr_value,
                    'expression_kind': expr_kind,
                    'params': header.params,
                }
                classification = 'identity_helper' if expr_kind == 'parameter' else 'constant_helper'
                proof['call_count'] = self._count_identifier_calls(code, name, line_start, line_end) if name else 0
            removable = bool(name) and proof.get('call_count', 0) == 0
            snippet = code[line_start:line_end]
            findings.append(
                NoOpEvidence(
                    kind=classification,
                    name=name,
                    snippet=snippet,
                    start=line_start,
                    end=line_end,
                    proof=proof,
                    removable=removable,
                )
            )
        return findings

    def _detect_noop_loops(self, code: str) -> List[NoOpEvidence]:
        loop_patterns = [
            re.compile(r'for\s+(?P<header>[^\n]*?)\s+do(?P<body>.*?)end', re.IGNORECASE | re.DOTALL),
            re.compile(r'while\s+(?P<header>[^\n]*?)\s+do(?P<body>.*?)end', re.IGNORECASE | re.DOTALL),
            re.compile(r'repeat(?P<body>.*?)until\s+(?P<condition>[^\n;]+)', re.IGNORECASE | re.DOTALL),
        ]
        matches: List[tuple[NoOpEvidence, str]] = []
        keys: List[str] = []
        for regex in loop_patterns:
            for match in regex.finditer(code):
                body = match.group('body')
                if self._strip_comments_and_strings(body).strip():
                    continue
                start, end = match.span()
                line_start, line_end = self._expand_to_line(code, start, end)
                snippet = code[line_start:line_end]
                normalised = self._normalise_snippet(snippet)
                keys.append(normalised)
                proof: Dict[str, Any] = {
                    'analysis': 'loop body empty after removing comments and literals',
                    'header': match.groupdict().get('header', '').strip(),
                }
                if 'condition' in match.groupdict():
                    proof['condition'] = match.group('condition').strip()
                evidence = NoOpEvidence(
                    kind='junk_loop',
                    name=None,
                    snippet=snippet,
                    start=line_start,
                    end=line_end,
                    proof=proof,
                    removable=True,
                )
                matches.append((evidence, normalised))
        counter = Counter(keys)
        findings: List[NoOpEvidence] = []
        for evidence, key in matches:
            updated_proof = dict(evidence.proof)
            updated_proof['duplicate_count'] = counter[key]
            findings.append(
                NoOpEvidence(
                    kind=evidence.kind,
                    name=evidence.name,
                    snippet=evidence.snippet,
                    start=evidence.start,
                    end=evidence.end,
                    proof=updated_proof,
                    removable=True,
                )
            )
        return findings

    def _extract_simple_return(self, body: str) -> Optional[tuple[str, str]]:
        stripped = body.strip()
        if not stripped.lower().startswith('return'):
            return None
        remainder = stripped[len('return'):].strip()
        if not remainder:
            return ('constant', 'nil')
        first_line, *rest = remainder.splitlines()
        if any(line.strip() for line in rest):
            return None
        expr = first_line.rstrip(';').strip()
        if not expr or ',' in expr:
            return None
        lowered = expr.lower()
        if lowered in {'nil', 'true', 'false'}:
            return ('constant', lowered)
        if lowered.startswith('0x') or lowered.startswith('0b'):
            try:
                int(lowered[2:], 16 if lowered.startswith('0x') else 2)
            except ValueError:
                return None
            return ('constant', expr)
        if lowered.replace('.', '', 1).isdigit():
            return ('constant', expr)
        if expr in {'...',}:
            return ('parameter', expr)
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', expr):
            return ('parameter', expr)
        if expr.startswith('"') or expr.startswith("'") or expr.startswith('['):
            return ('constant', expr)
        return None

    def _normalise_snippet(self, snippet: str) -> str:
        return re.sub(r'\s+', ' ', snippet.strip())

    def _expand_to_line(self, text: str, start: int, end: int) -> tuple[int, int]:
        line_start = text.rfind('\n', 0, start)
        if line_start == -1:
            line_start = 0
        else:
            line_start += 1
        line_end = text.find('\n', end)
        if line_end == -1:
            line_end = len(text)
        else:
            line_end += 1
        return line_start, line_end

    def _strip_comments_and_strings(self, text: str) -> str:
        text = _LONG_COMMENT_RE.sub(' ', text)
        text = _LINE_COMMENT_RE.sub(' ', text)
        text = _LONG_BRACKET_RE.sub(' ', text)
        text = _SHORT_STRING_RE.sub(' ', text)
        return text

    def _remove_comments(self, text: str) -> str:
        text = _LONG_COMMENT_RE.sub('', text)
        text = _LINE_COMMENT_RE.sub('', text)
        return text

    def _count_identifier_calls(self, code: str, name: Optional[str], start: int, end: int) -> int:
        if not name:
            return 0
        masked = code[:start] + (' ' * (end - start)) + code[end:]
        pattern = re.compile(rf'\b{re.escape(name)}\s*\(')
        return len(pattern.findall(masked))

    def detect_anti_debug_checks(self, code: str) -> List[str]:
        """Detect specific anti-debugging checks."""
        anti_debug_patterns = [
            r'debug\.getinfo\s*\(\s*\d+\s*\)',
            r'string\.dump\s*\([^)]+\)',
            r'getfenv\s*\(\s*0\s*\)',
            r'coroutine\.running\s*\(\s*\)',
            r'collectgarbage\s*\(\s*["\']count["\'].*?\)',
            r'os\.clock\s*\(\s*\).*?os\.clock\s*\(\s*\)',
        ]
        detected_checks = []
        for pattern in anti_debug_patterns:
            detected_checks.extend(re.findall(pattern, code, re.IGNORECASE | re.DOTALL))
        return detected_checks

    def sanitize_code(
        self,
        code: str,
        *,
        remove_noops: bool = False,
        confirm: bool = False,
    ) -> str:
        """Perform comprehensive code sanitization.

        Parameters
        ----------
        code:
            Lua source to sanitise.
        remove_noops:
            When ``True`` the detector attempts to strip junk helpers and
            no-op loops that have been proven to be side-effect free.  This
            requires explicit confirmation via ``confirm``.
        confirm:
            Must be set to ``True`` when ``remove_noops`` is requested.  This
            acts as a safety latch so callers make an intentional choice before
            any code-removal is performed.
        """
        self.logger.info("Starting comprehensive trap detection and removal...")
        self.detect_traps(code)
        cleaned_code = self.remove_traps(code)
        cleaned_code = self.neutralize_advanced_traps(cleaned_code)
        self.analyze_function_complexity(cleaned_code)
        self.detect_anti_debug_checks(cleaned_code)
        self.last_noop_report = self.detect_noop_insertions(cleaned_code)
        if remove_noops:
            if not confirm:
                raise ValueError(
                    "Explicit confirmation required before removing proven no-op blocks"
                )
            cleaned_code = self._strip_marked_noops(cleaned_code, self.last_noop_report)
        return cleaned_code

    def noop_report(self) -> List[Dict[str, Any]]:
        """Return the last computed no-op evidence in serialisable form."""

        return [entry.to_json() for entry in self.last_noop_report]
    # Advanced trap neutralisation
    def neutralize_advanced_traps(self, code: str) -> str:
        """Replace advanced anti-debug checks with benign stubs.

        This makes line number checks via ``debug.getinfo`` return a static value,
        forces ``pcall`` to always succeed and neuters ``string.dump`` based
        integrity verification.  It further sanitises metatable tricks, nil
        indexers and debug hooks so execution can continue without triggering
        protections.
        """

        stubs: List[str] = []
        added: set[str] = set()

        def add_stub(name: str, definition: str) -> None:
            if name not in added:
                added.add(name)
                stubs.append(definition)

        if re.search(r'\[\s*nil\s*\]', code):
            code = re.sub(r'\[\s*nil\s*\]', '[__nil_index_guard()]', code)
            add_stub('__nil_index_guard', 'local function __nil_index_guard() return 0 end')

        if re.search(r'debug\.getinfo', code):
            code = re.sub(r'debug\.getinfo', 'debug_getinfo_stub', code)
            add_stub('debug_getinfo_stub', 'local function debug_getinfo_stub(...) return {currentline=0} end')

        if re.search(r'\bpcall\b', code):
            code = re.sub(r'\bpcall\b', 'pcall_stub', code)
            add_stub('pcall_stub', 'local function pcall_stub(f, ...) return true, f(...) end')

        if re.search(r'\bxpcall\b', code):
            code = re.sub(r'\bxpcall\b', 'xpcall_stub', code)
            add_stub('xpcall_stub', 'local function xpcall_stub(f, handler, ...) return f(...) end')

        if re.search(r'string\.dump', code):
            code = re.sub(r'string\.dump', 'dump_stub', code)
            add_stub('dump_stub', 'local function dump_stub(_) return "" end')

        if re.search(r'debug\.sethook', code):
            code = re.sub(r'debug\.sethook', 'debug_sethook_stub', code)
            add_stub('debug_sethook_stub', 'local function debug_sethook_stub(...) return end')

        if re.search(r'debug\.gethook', code):
            code = re.sub(r'debug\.gethook', 'debug_gethook_stub', code)
            add_stub('debug_gethook_stub', 'local function debug_gethook_stub(...) return nil end')

        if re.search(r'debug\.traceback', code):
            code = re.sub(r'debug\.traceback', 'debug_traceback_stub', code)
            add_stub('debug_traceback_stub', 'local function debug_traceback_stub(...) return "" end')

        if re.search(r'\bsetmetatable\b', code):
            code = re.sub(r'\bsetmetatable\b', 'setmetatable_stub', code)
            add_stub('setmetatable_stub', 'local function setmetatable_stub(tbl, mt) return tbl end')

        if re.search(r'\bgetmetatable\b', code):
            code = re.sub(r'\bgetmetatable\b', 'getmetatable_stub', code)
            add_stub('getmetatable_stub', 'local function getmetatable_stub(tbl) return {} end')

        if re.search(r'debug\.getmetatable', code):
            code = re.sub(r'debug\.getmetatable', 'debug_getmetatable_stub', code)
            add_stub('debug_getmetatable_stub', 'local function debug_getmetatable_stub(tbl) return {} end')

        if re.search(r'\bsetfenv\b', code):
            code = re.sub(r'\bsetfenv\b', 'setfenv_stub', code)
            add_stub('setfenv_stub', 'local function setfenv_stub(fn, env) return fn end')

        if re.search(r'\bgetfenv\b', code):
            code = re.sub(r'\bgetfenv\b', 'getfenv_stub', code)
            add_stub('getfenv_stub', 'local function getfenv_stub(level) return _G end')

        if added:
            code = '\n'.join(stubs) + '\n' + code

        return code
