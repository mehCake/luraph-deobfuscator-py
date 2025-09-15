from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from src.exceptions import VMEmulationError
from src.vm.state import VMState
from src.vm.opcodes import OPCODE_HANDLERS, HandlerResult


class LuraphVM:
    """Simple stack-based virtual machine for experimental devirtualisation.

    The emulator executes instructions defined by ``bytecode`` using the
    functions from :mod:`vm.opcodes`.  The design intentionally keeps state and
    opcode handlers separate so more advanced techniques like symbolic
    execution can hook into the process in future iterations.
    """

    def __init__(
        self,
        constants: Optional[List[Any]] = None,
        bytecode: Optional[List[List[Any]]] = None,
        env: Optional[Dict[str, Any]] = None,
        *,
        symbolic: bool = False,
    ) -> None:
        """Create a new VM instance.

        ``constants`` and ``bytecode`` may be provided up-front or loaded later
        via :meth:`load_bytecode` which accepts a JSON payload.  The constructor
        always initialises a default global environment containing ``print``.
        """

        environment = {"print": print}
        if env:
            environment.update(env)
        self.state = VMState(
            constants=constants or [],
            bytecode=bytecode or [],
            env=environment,
            symbolic=symbolic,
        )
        self.logger = logging.getLogger(__name__)
        self._result: Any = None

    # ------------------------------------------------------------------
    def load_bytecode(self, payload: str) -> None:
        """Parse a JSON *payload* and populate the VM state.

        The function also performs LPH string decryption on the constants table
        using :func:`src.utils.decrypt_lph_string`.  ``VMEmulationError`` is
        raised when the payload cannot be parsed.
        """

        try:
            data: Any = json.loads(payload)
        except Exception as exc:  # pragma: no cover - exercise error path
            raise VMEmulationError("invalid bytecode payload") from exc

        constants = data.get("constants")
        bytecode = data.get("bytecode")
        if not isinstance(constants, list) or not isinstance(bytecode, list):
            raise VMEmulationError("malformed bytecode payload")

        from src.utils import decrypt_lph_string, _is_printable

        self.state.constants = []
        for c in constants:
            if isinstance(c, str):
                dec = decrypt_lph_string(c)
                self.state.constants.append(dec if _is_printable(dec) else c)
            else:
                self.state.constants.append(c)
        self.state.bytecode = bytecode
        self.state.pc = 0
        self.state.stack.clear()

    # ------------------------------------------------------------------
    def step(self) -> Optional[Any]:
        """Execute a single instruction and return a result if available."""
        state = self.state
        if state.pc >= len(state.bytecode):
            return None

        instr = state.bytecode[state.pc]
        op = instr[0]
        args = instr[1:]
        self.logger.debug("Executing %s %s", op, args)

        handler = OPCODE_HANDLERS.get(op)
        if handler is None:
            raise VMEmulationError(f"Unknown opcode: {op}")

        advance, result = handler(state, *args)
        state.pc += advance
        if result is not None:
            self._result = result
        return result

    # ------------------------------------------------------------------
    def run(self) -> Any:
        """Execute instructions until completion and return the last result."""
        while self.state.pc < len(self.state.bytecode):
            res = self.step()
            if res is not None:
                break
        return self._result


__all__ = ["LuraphVM"]
