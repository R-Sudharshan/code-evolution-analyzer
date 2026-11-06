"""CVSS 4.0 scoring — faithful port of the official FIRST, Inc.
cvss-v4-calculator JS reference implementation (BSD-2-Clause):

  resources/cvss_lookup.json  -> intelligence/data/cvss_lookup.json
  max_composed.js             -> intelligence/data/max_composed.json
  max_severity.js             -> intelligence/data/max_severity.json
  cvss_score.js, cvss_lookup.js logic -> functions below

Scores come exclusively from the official lookup table + documented algorithm.
Nothing is invented: if a vector is incomplete/invalid, we raise.
"""

import json
import math
import os
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "data"
_lookup = json.loads((_DATA_DIR / "cvss_lookup.json").read_text())
_max_composed = json.loads((_DATA_DIR / "max_composed.json").read_text())
_max_severity = json.loads((_DATA_DIR / "max_severity.json").read_text())

VALID = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN",
    "SC": "HLN", "SI": "SHLN", "SA": "SHLN",
    "E": "XAPU", "S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XHML", "RE": "XHML", "U": "XNCL",
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
    "MVC": "XHLN", "MVI": "XHLN", "MVA": "XHLN", "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN",
}
REQUIRED = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

AV_levels = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
PR_levels = {"N": 0.0, "L": 0.1, "H": 0.2}
UI_levels = {"N": 0.0, "P": 0.1, "A": 0.2}
AC_levels = {"L": 0.0, "H": 0.1}
AT_levels = {"N": 0.0, "P": 0.1}
VC_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
VI_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
VA_levels = {"H": 0.0, "L": 0.1, "N": 0.2}
SC_levels = {"H": 0.1, "L": 0.2, "N": 0.3}
SI_levels = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
SA_levels = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
CR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}
IR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}
AR_levels = {"H": 0.0, "M": 0.1, "L": 0.2}


class CVSS4Error(ValueError):
    pass


def parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith("CVSS:4.0/"):
        raise CVSS4Error("vector must start with CVSS:4.0/")
    out: dict[str, str] = {}
    for part in vector[len("CVSS:4.0/"):].split("/"):
        if ":" not in part:
            raise CVSS4Error(f"malformed vector segment: {part!r}")
        k, v = part.split(":", 1)
        if k in out:
            raise CVSS4Error(f"duplicate metric {k}")
        if k not in VALID or v not in VALID[k]:
            raise CVSS4Error(f"invalid metric/value {part!r}")
        out[k] = v
    missing = [m for m in REQUIRED if m not in out]
    if missing:
        raise CVSS4Error(f"missing required base metrics: {','.join(missing)}")
    return out


def _m(cvssSelected: dict, metric: str) -> str:
    selected = cvssSelected.get(metric)
    if metric == "E" and selected in (None, "X"):
        return "A"
    if metric in ("CR", "IR", "AR") and selected in (None, "X"):
        return "H"
    if metric not in (None, "X") and select_valid(selected, metric):
        pass
    mod_key = "M" + metric
    if mod_key in cvssSelected and cvssSelected[mod_key] != "X":
        return cvssSelected[mod_key]
    if selected is None:
        # environmental metrics only: use base value or invalid request
        raise CVSS4Error(f"metric {metric} missing")
    return selected


def select_valid(v: str, metric: str) -> bool:
    return v in VALID.get(metric, "")


def macro_vector(cvssSelected: dict) -> str:
    def mm(metric, default=None):
        try:
            return _m(cvssSelected, metric)
        except CVSS4Error:
            return default
    AV, PR, UI = _m(cvssSelected, "AV"), _m(cvssSelected, "PR"), _m(cvssSelected, "UI")
    if AV == "N" and PR == "N" and UI == "N":
        eq1 = "0"
    elif (AV == "N" or PR == "N" or UI == "N") and not (AV == "N" and PR == "N" and UI == "N") and not (AV == "P"):
        eq1 = "1"
    elif AV == "P" or not (AV == "N" or PR == "N" or UI == "N"):
        eq1 = "2"
    else:
        eq1 = "2"

    AC, AT = _m(cvssSelected, "AC"), _m(cvssSelected, "AT")
    eq2 = "0" if (AC == "L" and AT == "N") else "1"

    VC, VI, VA = _m(cvssSelected, "VC"), _m(cvssSelected, "VI"), _m(cvssSelected, "VA")
    if VC == "H" and VI == "H":
        eq3 = 0
    elif not (VC == "H" and VI == "H") and (VC == "H" or VI == "H" or VA == "H"):
        eq3 = 1
    else:
        eq3 = 2

    SC, SI, SA = _m(cvssSelected, "SC"), _m(cvssSelected, "SI"), _m(cvssSelected, "SA")
    MSI = cvssSelected.get("MSI", "X")
    MSA = cvssSelected.get("MSA", "X")
    if MSI == "S" or MSA == "S":
        eq4 = 0
    elif not (MSI == "S" or MSA == "S") and (SC == "H" or SI == "H" or SA == "H"):
        eq4 = 1
    else:
        eq4 = 2

    E = _m(cvssSelected, "E")
    eq5 = 0 if E == "A" else (1 if E == "P" else 2)

    CR, IR, AR = _m(cvssSelected, "CR"), _m(cvssSelected, "IR"), _m(cvssSelected, "AR")
    if (
        (CR == "H" and VC == "H")
        or (IR == "H" and VI == "H")
        or (AR == "H" and VA == "H")
    ):
        eq6 = 0
    else:
        eq6 = 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _eq_maxes(macro: str, eq: int):
    return _max_composed["eq" + str(eq)][macro[eq - 1]]


def _extract_value_metric(metric: str, max_vector: str) -> str:
    extracted = max_vector[max_vector.find(metric + ":") + len(metric) + 1:]
    return extracted.split("/")[0]


def _lookup_score_safe(macro: str):
    return _lookup.get(macro)


def cvss_score(vector: str) -> tuple[float, str]:
    """Returns (score, macroVector) exactly like the official calculator."""
    sel = parse_vector(vector)
    # shortcut: no impact on any system/confidentiality dimension -> 0
    # (uses the EFFECTIVE values, modified metrics included)
    if all(_m(sel, mmk) == "N" for mmk in ["VC", "VI", "VA", "SC", "SI", "SA"]):
        return 0.0, macro_vector(sel)
    macro = macro_vector(sel)
    value = _lookup_score_safe(macro)
    if value is None:
        raise CVSS4Error(f"macro vector {macro} missing from official lookup")
    eq1, eq2, eq3, eq4, eq5, eq6 = [int(c) for c in macro]
    eq1_next_lower = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next_lower = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"
    if eq3 == 1 and eq6 == 1:
        eq3eq6_next_lower = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 0 and eq6 == 1:
        eq3eq6_next_lower = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 1 and eq6 == 0:
        eq3eq6_next_lower = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
    elif eq3 == 0 and eq6 == 0:
        eq3eq6_next_lower_left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        eq3eq6_next_lower_right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    else:
        eq3eq6_next_lower = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"
    eq4_next_lower = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_next_lower = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    s_eq1n = _lookup_score_safe(eq1_next_lower)
    s_eq2n = _lookup_score_safe(eq2_next_lower)
    if eq3 == 0 and eq6 == 0:
        sl = _lookup_score_safe(eq3eq6_next_lower_left)
        srr = _lookup_score_safe(eq3eq6_next_lower_right)
        slv = sl if sl is not None else -1
        srv = srr if srr is not None else -1
        s_eq3eq6n = sl if slv > srv else srr
    else:
        s_eq3eq6n = _lookup_score_safe(eq3eq6_next_lower)
    s_eq4n = _lookup_score_safe(eq4_next_lower)
    s_eq5n = _lookup_score_safe(eq5_next_lower)

    eq1_maxes = _eq_maxes(macro, 1)
    eq2_maxes = _eq_maxes(macro, 2)
    eq3_eq6_maxes = _max_composed["eq3"][macro[2]][macro[5]]
    eq4_maxes = _eq_maxes(macro, 4)
    eq5_maxes = _eq_maxes(macro, 5)

    max_vectors = []
    for m1 in eq1_maxes:
        for m2 in eq2_maxes:
            for m3 in eq3_eq6_maxes:
                for m4 in eq4_maxes:
                    for m5 in eq5_maxes:
                        max_vectors.append(m1 + m2 + m3 + m4 + m5)

    def sd_metric(levels, metric, mv):
        return levels[_m(sel, metric)] - levels[_extract_value_metric(metric, mv)]

    def distance_for(max_vector: str):
        sd_av = sd_metric(AV_levels, "AV", max_vector)
        sd_pr = sd_metric(PR_levels, "PR", max_vector)
        sd_ui = sd_metric(UI_levels, "UI", max_vector)
        sd_ac = sd_metric(AC_levels, "AC", max_vector)
        sd_at = sd_metric(AT_levels, "AT", max_vector)
        sd_vc = sd_metric(VC_levels, "VC", max_vector)
        sd_vi = sd_metric(VI_levels, "VI", max_vector)
        sd_va = sd_metric(VA_levels, "VA", max_vector)
        sd_sc = sd_metric(SC_levels, "SC", max_vector)
        sd_si = sd_metric(SI_levels, "SI", max_vector)
        sd_sa = sd_metric(SA_levels, "SA", max_vector)
        sd_cr = sd_metric(CR_levels, "CR", max_vector)
        sd_ir = sd_metric(IR_levels, "IR", max_vector)
        sd_ar = sd_metric(AR_levels, "AR", max_vector)
        dists = [sd_av, sd_pr, sd_ui, sd_ac, sd_at, sd_vc, sd_vi, sd_va, sd_sc, sd_si, sd_sa, sd_cr, sd_ir, sd_ar]
        if any(d < 0 for d in dists):
            return None
        return (
            sd_av + sd_pr + sd_ui,
            sd_ac + sd_at,
            sd_vc + sd_vi + sd_va + sd_cr + sd_ir + sd_ar,
            sd_sc + sd_si + sd_sa,
            0,
        )

    chosen = None
    last = (0, 0, 0, 0, 0)

    def evaluate(max_vector: str):
        """Returns (ok, dists); distances of rejected candidates are still valid data."""
        sds = {
            "AV": AV_levels[_m(sel, "AV")] - AV_levels[_extract_value_metric("AV", max_vector)],
            "PR": PR_levels[_m(sel, "PR")] - PR_levels[_extract_value_metric("PR", max_vector)],
            "UI": UI_levels[_m(sel, "UI")] - UI_levels[_extract_value_metric("UI", max_vector)],
            "AC": AC_levels[_m(sel, "AC")] - AC_levels[_extract_value_metric("AC", max_vector)],
            "AT": AT_levels[_m(sel, "AT")] - AT_levels[_extract_value_metric("AT", max_vector)],
            "VC": VC_levels[_m(sel, "VC")] - VC_levels[_extract_value_metric("VC", max_vector)],
            "VI": VI_levels[_m(sel, "VI")] - VI_levels[_extract_value_metric("VI", max_vector)],
            "VA": VA_levels[_m(sel, "VA")] - VA_levels[_extract_value_metric("VA", max_vector)],
            "SC": SC_levels[_m(sel, "SC")] - SC_levels[_extract_value_metric("SC", max_vector)],
            "SI": SI_levels[_m(sel, "SI")] - SI_levels[_extract_value_metric("SI", max_vector)],
            "SA": SA_levels[_m(sel, "SA")] - SA_levels[_extract_value_metric("SA", max_vector)],
            "CR": CR_levels[_m(sel, "CR")] - CR_levels[_extract_value_metric("CR", max_vector)],
            "IR": IR_levels[_m(sel, "IR")] - IR_levels[_extract_value_metric("IR", max_vector)],
            "AR": AR_levels[_m(sel, "AR")] - AR_levels[_extract_value_metric("AR", max_vector)],
        }
        vals = list(sds.values())
        return (all(v >= 0 for v in vals), (
            sds["AV"] + sds["PR"] + sds["UI"],
            sds["AC"] + sds["AT"],
            sds["VC"] + sds["VI"] + sds["VA"] + sds["CR"] + sds["IR"] + sds["AR"],
            sds["SC"] + sds["SI"] + sds["SA"],
            0,
        ))

    for max_vector in max_vectors:
        ok, dists = evaluate(max_vector)
        last = dists
        if ok:
            chosen = dists
            break
    # official JS reference semantics: if no candidate passes, the distances of
    # the last evaluated candidate are used as-is (reference behavior).
    d_eq1, d_eq2, d_eq3eq6, d_eq4, d_eq5 = chosen if chosen is not None else last

    step = 0.1
    n_existing_lower = 0
    normalized = [0.0, 0.0, 0.0, 0.0, 0.0]

    def composed(available, current, max_severity_value, index: int):
        nonlocal n_existing_lower
        if available is None:
            return
        n_existing_lower += 1
        percent = (current / max_severity_value) if max_severity_value else 0
        normalized[index] = available * percent

    composed(None if s_eq1n is None else value - s_eq1n, d_eq1, _max_severity["eq1"][str(eq1)] * step, 0)
    composed(None if s_eq2n is None else value - s_eq2n, d_eq2, _max_severity["eq2"][str(eq2)] * step, 1)
    composed(
        None if s_eq3eq6n is None else value - s_eq3eq6n,
        d_eq3eq6,
        _max_severity["eq3eq6"][str(eq3)][str(eq6)] * step,
        2,
    )
    composed(None if s_eq4n is None else value - s_eq4n, d_eq4, _max_severity["eq4"][str(eq4)] * step, 3)
    composed(None if s_eq5n is None else value - s_eq5n, 0, 1.0 * step, 4)  # eq5 percentage is always 0

    if n_existing_lower == 0:
        mean_distance = 0
    else:
        mean_distance = sum(normalized) / n_existing_lower

    value -= mean_distance
    value = max(0.0, min(10.0, value))
    # JS Math.round (half away from zero) rather than python banker's rounding
    return math.floor(value * 10 + 0.5) / 10, macro


def severity_band(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
