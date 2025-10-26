from src import utils


def test_detect_secret_candidates_stripe_key() -> None:
    token = "sk_live_0123456789abcdef012345"
    text = f"return '{token}'"

    findings = utils.detect_secret_candidates(text)

    assert findings, "expected stripe key to be detected"
    assert findings[0].category == "stripe_secret_key"

    masked = findings[0].masked()
    assert token not in masked
    assert masked.startswith("sk_l"), "masked value should retain a short prefix"

    sanitized, metadata = utils.sanitize_secret_candidates(text, findings)
    assert "<redacted:stripe_secret_key>" in sanitized
    assert metadata and metadata[0]["category"] == "stripe_secret_key"
    assert metadata[0]["replacement"] == "<redacted:stripe_secret_key>"
    assert token not in metadata[0]["masked_value"]


def test_detect_secret_candidates_keyword_assignment() -> None:
    token = "ABCD1234EFGH5678IJKL90"
    text = f'local apiKey = "{token}"'

    findings = utils.detect_secret_candidates(text)

    assert findings, "keyword based API key should be flagged"
    assert findings[0].category == "keyword_assignment"

    sanitized, metadata = utils.sanitize_secret_candidates(text, findings)
    assert "<redacted:keyword_assignment>" in sanitized
    assert metadata[0]["category"] == "keyword_assignment"
    assert token not in metadata[0]["masked_value"]
