from orca.checks.cve import _odoo_version_applicability


def _cve_with_matches(matches):
    return {"configurations": [{"nodes": [{"cpeMatch": matches}]}]}


def test_exact_odoo_cpe_excludes_other_major_versions() -> None:
    cve = _cve_with_matches(
        [
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:odoo:odoo:15.0:*:*:*:enterprise:*:*:*",
            }
        ]
    )

    assert _odoo_version_applicability(cve, "19") is False
    assert _odoo_version_applicability(cve, "15.0") is True


def test_odoo_cpe_range_is_evaluated() -> None:
    cve = _cve_with_matches(
        [
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:odoo:odoo:*:*:*:*:enterprise:*:*:*",
                "versionStartIncluding": "11.0",
                "versionEndIncluding": "14.0",
            }
        ]
    )

    assert _odoo_version_applicability(cve, "14") is True
    assert _odoo_version_applicability(cve, "19") is False


def test_package_specific_candidate_without_odoo_cpe_is_unconfirmed() -> None:
    cve = {"configurations": []}

    assert _odoo_version_applicability(cve, "19") is None
