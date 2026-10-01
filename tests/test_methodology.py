from orca.methodology import build_methodology_artifact


def test_methodology_represents_every_current_owasp_category() -> None:
    artifact = build_methodology_artifact(["crawler", "misconfig", "xss"])

    assert artifact["framework"] == "OWASP Top 10:2025"
    assert [category["id"] for category in artifact["categories"]] == [
        f"A{index:02d}:2025" for index in range(1, 11)
    ]


def test_methodology_distinguishes_external_and_internal_coverage() -> None:
    artifact = build_methodology_artifact(["crawler", "misconfig", "xss"])
    categories = {item["id"]: item for item in artifact["categories"]}

    assert categories["A01:2025"]["status"] == "focused"
    assert categories["A01:2025"]["executed_checks"] == ["crawler"]
    assert categories["A03:2025"]["status"] == "not_run"
    assert categories["A09:2025"]["status"] == "not_externally_verifiable"
    assert "code-review workflow" in artifact["limitations"][1]
