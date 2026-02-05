from dataclasses import dataclass, field
from types import SimpleNamespace

from opcode_lifter import BootstrapIR
from pattern_analyzer import CacheSlot, SerializedChunk, SerializedChunkDescriptor
from string_decryptor import StringDecoderDescriptor

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


def test_runtime_ir_annotation_pass_tracks_f3_usage_contexts() -> None:
    bootstrap = BootstrapIR(
        cache_slots=[
            CacheSlot(
                index_literal="0x1",
                index_value=1,
                expressions=["F3[1] = 1"],
                classification="constant",
                semantic_role="string token",
            ),
            CacheSlot(
                index_literal="0x2",
                index_value=2,
                expressions=["F3[2] = 2"],
                classification="constant",
                semantic_role="serialized blob offset",
            ),
            CacheSlot(
                index_literal="0x3",
                index_value=3,
                expressions=["F3[3] = 3"],
                classification="constant",
                semantic_role="vm arithmetic seed",
            ),
            CacheSlot(
                index_literal="0x4",
                index_value=4,
                expressions=["F3[4] = 4"],
                classification="constant",
                semantic_role="guard value",
            ),
        ],
        string_decoder=StringDecoderDescriptor(
            closure_variable="t",
            invocation="return F3[1]",
            gsub_alias="g",
            metatable_alias="mt",
            cache_table="F3",
            token_variable="token",
            token_length=16,
            local_variable_count=3,
            caches_results=True,
        ),
        serialized_chunk=SerializedChunk(
            descriptor=SerializedChunkDescriptor(
                buffer_name="payload",
                initial_offset=0,
                helper_functions={"reader": "return F3[2]"},
            )
        ),
    )

    vm_entry = MockVMEntry(
        control_variable="state",
        captures={
            "dispatcher": "acc = acc + F3[3]",
            "fallback_path": "-- rare handler\nreturn F3[4]",
        },
    )

    annotator = RuntimeIRAnnotationPass()
    summary = annotator.run(bootstrap, vm_entry)

    usage = summary.slot_usage
    assert usage[1]["used_in_string_decoder"] is True
    assert usage[1]["used_in_serialized_data"] is False
    assert usage[1]["used_in_vm_core"] is False
    assert usage[1]["rarely_referenced"] is False

    assert usage[2]["used_in_serialized_data"] is True
    assert usage[2]["used_in_vm_core"] is False

    assert usage[3]["used_in_vm_core"] is True
    assert usage[3]["rarely_referenced"] is False

    assert usage[4]["rarely_referenced"] is True
    assert usage[4]["used_in_vm_core"] is False

    constant_cache_annotations = bootstrap.annotations["runtime"]["constant_cache"]
    assert str(1) in constant_cache_annotations["slot_usage"]
    assert constant_cache_annotations["rare_slots"] == [4]
