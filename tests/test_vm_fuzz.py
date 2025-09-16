import random
from typing import List, Sequence

from src.vm.emulator import LuraphVM

_ARITH_OPS = ("ADD", "SUB", "MUL", "BXOR")


def _push_value(rng: random.Random, instructions: list[list[object]], constants: Sequence[int]) -> None:
    if constants and rng.random() < 0.5:
        idx = rng.randrange(len(constants))
        instructions.append(["LOADK", idx])
    else:
        instructions.append(["LOADN", rng.randint(-64, 64)])


def _build_program(rng: random.Random) -> tuple[list[int], list[list[object]]]:
    constants = [rng.randint(-64, 64) for _ in range(rng.randint(1, 4))]
    instructions: list[list[object]] = []
    stack_depth = 0

    for _ in range(2):
        _push_value(rng, instructions, constants)
        stack_depth += 1

    for _ in range(rng.randint(1, 6)):
        if stack_depth < 2 or rng.random() < 0.55:
            _push_value(rng, instructions, constants)
            stack_depth += 1
        else:
            op = rng.choice(_ARITH_OPS)
            instructions.append([op])
            stack_depth -= 1

    while stack_depth < 1:
        _push_value(rng, instructions, constants)
        stack_depth += 1

    instructions.append(["RETURN"])
    return constants, instructions


def _execute_reference(constants: Sequence[int], bytecode: Sequence[Sequence[object]]) -> int:
    stack: List[int] = []
    for instr in bytecode:
        op = instr[0]
        if op == "LOADK":
            stack.append(constants[instr[1]])
        elif op == "LOADN":
            stack.append(instr[1])
        elif op == "ADD":
            b = stack.pop()
            a = stack.pop()
            stack.append(a + b)
        elif op == "SUB":
            b = stack.pop()
            a = stack.pop()
            stack.append(a - b)
        elif op == "MUL":
            b = stack.pop()
            a = stack.pop()
            stack.append(a * b)
        elif op == "BXOR":
            b = stack.pop()
            a = stack.pop()
            stack.append(int(a) ^ int(b))
        elif op == "RETURN":
            return stack.pop()
        else:  # pragma: no cover - defensive guard for new ops
            raise AssertionError(f"unexpected opcode {op}")
    raise AssertionError("program did not return")


def test_vm_fuzz_matches_reference():
    rng = random.Random(0xC0DE)
    for _ in range(100):
        constants, program = _build_program(rng)
        expected = _execute_reference(constants, program)
        vm = LuraphVM(constants=constants, bytecode=program, timeout=None)
        assert vm.run() == expected

