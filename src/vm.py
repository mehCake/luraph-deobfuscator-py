import logging
from typing import Any, Dict, List

class LuraphVM:
    """Minimal stack-based VM for experimentation.

    The goal of this class is to gradually grow into something that resembles
    Luraph's virtual machine.  It intentionally starts tiny and only supports a
    hand full of opcodes so devirtualisation logic can be developed
    incrementally.  Each progress step aims to add a few more instructions or
    features.
    """

    def __init__(
        self,
        constants: List[Any],
        bytecode: List[List[Any]],
        env: Dict[str, Any] | None = None,
    ):
        self.constants = constants
        self.bytecode = bytecode
        self.stack: List[Any] = []
        self.pc = 0
        self.logger = logging.getLogger(__name__)
        # Simple environment for GETGLOBAL/SETGLOBAL.  Users may pass in extra
        # symbols which will be merged into this dictionary.
        self.env: Dict[str, Any] = {"print": print}
        if env:
            self.env.update(env)

    def step(self) -> Any:
        if self.pc >= len(self.bytecode):
            return None
        instr = self.bytecode[self.pc]
        op = instr[0]
        args = instr[1:]
        self.logger.debug("Executing %s %s", op, args)

        advance = 1

        if op == "LOADK":
            idx = args[0]
            self.stack.append(self.constants[idx])
        elif op == "LOADN":
            # push a numeric constant directly supplied in the instruction
            self.stack.append(args[0])
        elif op in ("LOADBOOL", "LOADB"):
            # LOADB is an alias observed in some dumps; both funnel here
            self.stack.append(bool(args[0]))
        elif op == "LOADNIL":
            self.stack.append(None)
        elif op == "MOVE":
            # copy an existing stack value by index
            idx = args[0]
            self.stack.append(self.stack[idx])
        elif op == "GETGLOBAL":
            idx = args[0]
            name = self.constants[idx]
            self.stack.append(self.env.get(name))
        elif op == "SETGLOBAL":
            idx = args[0]
            value = self.stack.pop()
            name = self.constants[idx]
            self.env[name] = value
        elif op == "ADD":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a + b)
        elif op == "SUB":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a - b)
        elif op == "MUL":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a * b)
        elif op == "DIV":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a / b)
        elif op == "MOD":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a % b)
        elif op == "POW":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a ** b)
        elif op == "UNM":
            a = self.stack.pop()
            self.stack.append(-a)
        elif op == "BNOT":
            a = self.stack.pop()
            self.stack.append(~int(a))
        elif op == "BAND":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(int(a) & int(b))
        elif op == "BOR":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(int(a) | int(b))
        elif op == "BXOR":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(int(a) ^ int(b))
        elif op == "SHL":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(int(a) << int(b))
        elif op == "SHR":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(int(a) >> int(b))
        elif op == "CONCAT":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(str(a) + str(b))
        elif op == "EQ":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a == b)
        elif op == "NE":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a != b)
        elif op == "LT":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a < b)
        elif op == "LE":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a <= b)
        elif op == "GT":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a > b)
        elif op == "GE":
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(a >= b)
        elif op == "NOT":
            a = self.stack.pop()
            self.stack.append(not a)
        elif op == "NEWTABLE":
            self.stack.append({})
        elif op == "SETTABLE":
            value = self.stack.pop()
            key = self.stack.pop()
            table = self.stack.pop()
            table[key] = value
            self.stack.append(table)
        elif op == "GETTABLE":
            key = self.stack.pop()
            table = self.stack.pop()
            self.stack.append(table[key])
        elif op == "LEN":
            a = self.stack.pop()
            self.stack.append(len(a))
        elif op == "JMP":
            offset = args[0]
            advance = offset
        elif op == "JMPIF":
            offset = args[0]
            cond = self.stack.pop()
            if cond:
                advance = offset
        elif op == "JMPIFNOT":
            offset = args[0]
            cond = self.stack.pop()
            if not cond:
                advance = offset
        elif op == "FORPREP":
            # expects [start, limit, step] on stack
            step = self.stack.pop()
            limit = self.stack.pop()
            start = self.stack.pop()
            # Lua's FORPREP sets the initial value to start-step
            self.stack.extend([start - step, limit, step])
            advance = args[0]
        elif op == "FORLOOP":
            offset = args[0]
            step = self.stack[-1]
            limit = self.stack[-2]
            self.stack[-3] += step
            idx = self.stack[-3]
            if (step > 0 and idx <= limit) or (step <= 0 and idx >= limit):
                advance = offset
            else:
                # loop finished; drop control values
                self.stack.pop()  # step
                self.stack.pop()  # limit
                self.stack.pop()  # index
        elif op == "CALL":
            argc = args[0]
            func = self.stack.pop()
            call_args = [self.stack.pop() for _ in range(argc)][::-1]
            ret = func(*call_args)
            if ret is not None:
                self.stack.append(ret)
        elif op == "RETURN":
            self.pc = len(self.bytecode)
            return self.stack.pop() if self.stack else None
        else:
            self.logger.debug("Unknown opcode: %s", op)

        self.pc += advance
        return None

    def run(self) -> Any:
        result = None
        while self.pc < len(self.bytecode):
            res = self.step()
            if res is not None:
                result = res
                break
        return result

__all__ = ["LuraphVM"]
