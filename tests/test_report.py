import textwrap

from src.report import DeobReport


def test_report_to_text_includes_expected_sections():
    report = DeobReport(
        version_detected="luraph_v14_4_initv4",
        confirmed=True,
        script_key_used="x5elqj5j4ibv9z3329g7b",
        bootstrapper_used="examples/initv4.lua",
        blob_count=3,
        decoded_bytes=4096,
        payload_iterations=3,
        opcode_stats={"CALL": 5, "LOADK": 8},
        unknown_opcodes=[255],
        traps_removed=2,
        constants_decrypted=7,
        variables_renamed=12,
        output_length=2048,
        chunks=[
            {
                "index": 0,
                "size": 512,
                "decoded_byte_count": 256,
                "lifted_instruction_count": 42,
                "suspicious": False,
            }
        ],
        warnings=["extra metadata missing"],
        errors=["opcode 0x33 failed"],
    )

    rendered = report.to_text()

    expected = textwrap.dedent(
        """
        Detected version: luraph_v14_4_initv4
        User confirmed detection: yes
        Script key: x5elqj... (len=21)
        Bootstrapper: examples/initv4.lua
        Decoded 3 blobs, total 4096 bytes
        Payload iterations: 3
        Opcode counts:
          CALL: 5
          LOADK: 8
        Unknown opcodes: [255]
        Traps removed: 2
        Constants decrypted: 7
        Variables renamed: 12
        Final output length: 2048 chars
        Chunk summary:
          - chunk 0: size=512, decoded=256, lifted=42
        Warnings:
          - extra metadata missing
        Errors:
          - opcode 0x33 failed
        """
    ).strip()

    assert rendered == expected


def test_report_to_text_handles_missing_optional_fields():
    report = DeobReport(version_detected="luraph_v14_4_initv4")

    rendered = report.to_text().splitlines()

    assert rendered[0] == "Detected version: luraph_v14_4_initv4"
    assert rendered[1] == "User confirmed detection: no"
    assert "Script key" not in "\n".join(rendered)
    assert "Bootstrapper" not in "\n".join(rendered)
    assert "Unknown opcodes: none" in rendered
    assert any(line.startswith("Payload iterations:") for line in rendered)
    assert rendered[-1] == "Final output length: 0 chars"


def test_report_to_json_masks_script_key_and_chunks():
    report = DeobReport(
        version_detected="luraph_v14_4_initv4",
        script_key_used="abcdef123456",
        blob_count=2,
        decoded_bytes=512,
        payload_iterations=2,
        chunks=[
            {"index": 0, "size": 128, "decoded_byte_count": 64, "lifted_instruction_count": 10},
            {"index": 1, "size": 256, "decoded_byte_count": 128, "lifted_instruction_count": 20},
        ],
    )

    payload = report.to_json()

    assert payload["script_key_used"] == "abcdef... (len=12)"
    assert payload["blob_count"] == 2
    assert payload["payload_iterations"] == 2
    assert len(payload["chunks"]) == 2
    first_chunk = payload["chunks"][0]
    assert first_chunk["used_key_masked"] == "abcdef... (len=12)"
    assert first_chunk["decoded_byte_count"] == 64
