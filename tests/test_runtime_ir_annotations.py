from dataclasses import dataclass, field
from types import SimpleNamespace

from opcode_lifter import BootstrapIR
from pattern_analyzer import CacheSlot

from src.passes.runtime_ir_annotations import RuntimeIRAnnotationPass


@dataclass
class MockVMEntry:
    control_variable: str
    constant_cache_name: str = "F3"
    primitive_table_name: str = "C3"
    captures: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)


def test_runtime_ir_annotation_pass_labels_structures() -> None:
    bootstrap = BootstrapIR(
        cache_slots=[
            CacheSlot(
                index_literal="0x1",
                index_value=1,
                expressions=["F3[1] = 1"],
                classification="constant",
                semantic_role="test entry",
            )
        ],
        c3_primitives={"count": 5},
        serialized_chunk=None,
        string_decoder=None,
    )
    vm_entry = MockVMEntry(control_variable="x", captures={"state": "x"})

    annotator = RuntimeIRAnnotationPass()
    summary = annotator.run(bootstrap, vm_entry)

    runtime_annotations = bootstrap.annotations.get("runtime", {})
    assert runtime_annotations["constant_cache"]["label"] == "constant cache"
    assert runtime_annotations["constant_cache"]["slot_count"] == 1
    assert runtime_annotations["primitive_operations"]["label"] == "primitive operations table"
    assert summary.constant_cache_label == "constant cache"
    assert summary.primitive_table_label == "primitive operations table"

    entry_annotations = vm_entry.annotations.get("runtime", {})
    assert entry_annotations["control_state_machine"]["variable"] == "x"
    assert summary.control_state_machine == "x"

    # Ensure original structures remain intact.
    assert bootstrap.cache_slots[0].index_literal == "0x1"
    assert vm_entry.captures["state"] == "x"


def test_runtime_ir_annotation_pass_handles_missing_attributes() -> None:
    bootstrap = BootstrapIR()
    vm_entry = SimpleNamespace()

    annotator = RuntimeIRAnnotationPass()
    summary = annotator.run(bootstrap, vm_entry)

    assert summary.control_state_machine is None
    assert "runtime" in getattr(bootstrap, "annotations")
    assert "constant_cache" in bootstrap.annotations["runtime"]
