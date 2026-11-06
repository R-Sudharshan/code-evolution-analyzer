"""CVSS 4.0 test: port must match the FIRST cvss-v4-calculator reference vectors
(differentially verified at build time; subset pinned here incl. regression pairs)."""

import pytest

from backend.intelligence.cvss4 import CVSS4Error, cvss_score, severity_band, macro_vector, parse_vector

KNOWN = [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, "000100"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "002201"),
    ("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:H/SC:N/SI:L/SA:N", 5.8, "111200"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:L/SA:N", 7.1, "101200"),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:L/SI:N/SA:N", 2.4, "202201"),
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 1.0, "212201"),
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:S/E:A/IR:M/AR:H/MAV:A/MVI:N", 2.0, "112201"),
]


@pytest.mark.parametrize("vector,score,macro", KNOWN)
def test_known_vectors(vector, score, macro):
    got, gm = cvss_score(vector)
    assert got == pytest.approx(score)
    assert gm == macro


def test_shortcut_zero_uses_modified_metrics():
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/U:L"
    s, _ = cvss_score(base)  # supplemental only -> still 0
    assert s == 0.0


def test_invalid_vectors_rejected():
    with pytest.raises(CVSS4Error):
        cvss_score("CVSS:4.0/AV:N")  # incomplete
    with pytest.raises(CVSS4Error):
        cvss_score("AV:N/AC:L")  # missing prefix
    with pytest.raises(CVSS4Error):
        parse_vector("CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")  # invalid value
    with pytest.raises(CVSS4Error):
        parse_vector("CVSS:4.0/AV:A/AV:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")  # duplicate


def test_macro_vector_matches_official():
    assert macro_vector(parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")) == "000100"


def test_severity_bands():
    assert severity_band(9.5) == "Critical"
    assert severity_band(8.0) == "High"
    assert severity_band(5.5) == "Medium"
    assert severity_band(1.0) == "Low"
    assert severity_band(0.0) == "None"
