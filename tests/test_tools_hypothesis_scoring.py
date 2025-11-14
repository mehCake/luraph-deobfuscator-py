from src.tools.hypothesis_scoring import (
    HypothesisScore,
    estimate_english_likeliness,
    estimate_lua_token_density,
    score_mapping_coherence,
    score_parity_outcome,
    score_pipeline_hypothesis,
)


def test_estimate_english_likeliness_prefers_printable() -> None:
    readable = "local function greet() return 'hello world' end"
    noisy = "\x00\x01\x02\x03\x04"
    assert estimate_english_likeliness(readable) > 0.6
    assert estimate_english_likeliness(noisy) < 0.1


def test_estimate_lua_token_density_detects_keywords() -> None:
    payload = "local x = function(y) if y then return true end end"
    sparse = "print('hi')"
    assert estimate_lua_token_density(payload) > estimate_lua_token_density(sparse)


def test_score_mapping_coherence_blends_selection_confidence() -> None:
    candidates = [
        {
            "confidence": 0.4,
            "selections": {
                "0": {"confidence": 0.9},
                "1": {"confidence": 0.8},
            },
        }
    ]
    assert 0.4 < score_mapping_coherence(candidates) < 1.0


def test_score_pipeline_hypothesis_combines_components() -> None:
    hypothesis = score_pipeline_hypothesis(
        pipeline_confidence=0.8,
        english_scores=[0.6, 0.7],
        lua_scores=[0.5],
        parity={"success": True, "matching_prefix": 64, "limit": 64},
        mapping_candidates=[{"confidence": 0.75}],
    )
    assert isinstance(hypothesis, HypothesisScore)
    assert hypothesis.overall > 0.6
    assert hypothesis.components["pipeline"] == 0.8
    assert "Parity" not in "".join(hypothesis.notes)


def test_score_parity_outcome_handles_failure() -> None:
    parity = {"success": False, "matching_prefix": 16, "limit": 64}
    score = score_parity_outcome(parity)
    assert 0 < score < 0.2
