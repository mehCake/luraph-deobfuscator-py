from src.lifter_core import cluster_candidate_rankings


def test_cluster_candidate_rankings_merges_scores() -> None:
    run_one = {
        "1": {"candidates": ["MOVE", "OP_1", "RETURN"]},
        "2": {"candidates": ["LOADK", "GETGLOBAL"]},
    }
    run_two = {
        "1": {"candidates": ["MOVE", "RETURN", "OP_1"]},
        "2": {"candidates": ["GETGLOBAL", "LOADK"]},
    }
    clustered = cluster_candidate_rankings([run_one, run_two])
    assert clustered["1"][0] == "MOVE"
    assert clustered["1"][1] == "RETURN"
    assert clustered["2"][0] in {"GETGLOBAL", "LOADK"}
    assert set(clustered["2"][:2]) == {"GETGLOBAL", "LOADK"}
