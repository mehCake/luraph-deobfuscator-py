from src.versions import v14_3_helper_analysis as analysis


def test_helper_summary_contains_all_primary_helpers():
    expected = {"Y3", "o", "M", "r", "O3", "a3", "N", "C3"}
    assert expected.issubset(set(analysis.HELPER_SUMMARIES)), (
        "helper analysis is missing one or more summaries"
    )


def test_pipeline_description_mentions_key_schedule_and_token_hashing():
    text = analysis.PIPELINE_DESCRIPTION
    assert "N(u,0x5)" in text, "pipeline description must mention the key schedule"
    assert "base-85" in text, "pipeline description must mention token hashing"
