"""The radar (spider) chart block: model bounds and clamping, TikZ structure, key rows, greyscale, determinism."""
from __future__ import annotations

import math
from pathlib import Path
import re

import pytest

from appsec_review.reporting.latex import RADAR_LINE_STYLES, RADAR_R, radar_line_style, radar_point, render_latex
from appsec_review.reporting.model import Document, RadarAxis, RadarChart, RadarLegendRow, RadarSeries

TEMPLATE = Path(__file__).resolve().parents[3] / "containers" / "report" / "latex" / "template"
AXES = (RadarAxis("Memory safety", "M"), RadarAxis("Numeric handling", "N"), RadarAxis("Control and injection", "C"))
COORD = re.compile(r"-?\d+\.\d{3}")


def _doc(*blocks: object) -> Document:
    return Document(title="Radar", run_id="2026-11-16-0004", subtitle="", status_badge="COMPLETE", status_tone="confirmed",
                    source_date_epoch=0, ledger_head="ab" * 32, blocks=tuple(blocks))


def _body(document: Document) -> str:
    return render_latex(document, TEMPLATE).split(r"\begin{document}", 1)[1]


def _chart(**changes: object) -> RadarChart:
    base: dict[str, object] = dict(
        title="Coverage", axes=AXES,
        series=(RadarSeries("Confirmed findings", "confirmed", (0.0, 0.5, 1.0), ("0", "1", "2")),
                RadarSeries("Claims examined", "proposed", (1.0, 0.25, 0.5))),
        scale_note="1.0 is the largest axis.",
        legend=(RadarLegendRow("series", "Confirmed findings", "Confirmed findings", "confirmed packages"),
                RadarLegendRow("axis", "M", "Memory safety", "memory corruption")))
    base.update(changes)
    return RadarChart(**base)  # type: ignore[arg-type]


def test_axis_series_and_legend_bounds_are_enforced() -> None:
    with pytest.raises(ValueError, match="3 to 12 axes"):
        _chart(axes=AXES[:2], series=(RadarSeries("a", "neutral", (0.0, 0.0)),))
    thirteen = tuple(RadarAxis(f"axis {index}", f"k{index}") for index in range(13))
    with pytest.raises(ValueError, match="3 to 12 axes"):
        _chart(axes=thirteen, series=(RadarSeries("a", "neutral", (0.0,) * 13),))
    with pytest.raises(ValueError, match="1 to 4 series"):
        _chart(series=())
    with pytest.raises(ValueError, match="1 to 4 series"):
        _chart(series=tuple(RadarSeries(f"s{index}", "neutral", (0.0, 0.0, 0.0)) for index in range(5)))
    with pytest.raises(ValueError, match="has 2 values for 3 axes"):
        _chart(series=(RadarSeries("a", "neutral", (0.0, 1.0)),))
    with pytest.raises(ValueError, match="has 1 displays for 3 axes"):
        _chart(series=(RadarSeries("a", "neutral", (0.0, 1.0, 1.0), ("x",)),))
    with pytest.raises(ValueError, match="distinct"):
        _chart(axes=(AXES[0], AXES[1], RadarAxis("Other", "M")))
    with pytest.raises(ValueError, match="'series' or 'axis'"):
        _chart(legend=(RadarLegendRow("row", "x", "y", "z"),))
    twelve = tuple(RadarAxis(f"axis {index}", f"k{index}") for index in range(12))
    assert len(_chart(axes=twelve, series=(RadarSeries("a", "neutral", (0.5,) * 12),)).axes) == 12


def test_values_are_clamped_into_the_unit_range_and_the_clamping_is_recorded() -> None:
    chart = _chart(series=(RadarSeries("a", "neutral", (1.5, -0.2, math.nan)),
                           RadarSeries("b", "neutral", (math.inf, 0.5, True))), clamped=99)
    assert chart.series[0].values == (1.0, 0.0, 0.0) and chart.series[1].values == (1.0, 0.5, 0.0)
    assert chart.clamped == 5                          # a passed count is ignored; the construction counts
    assert "5 value(s) fell outside 0 to 1" in _body(_doc(chart))
    assert _chart().clamped == 0 and "fell outside" not in _body(_doc(_chart()))


def test_tikz_grid_polygons_rim_keys_legend_rows_and_greyscale_line_styles() -> None:
    body = _body(_doc(_chart()))
    tikz = body.split(r"\begin{tikzpicture}", 1)[1].split(r"\end{tikzpicture}", 1)[0]
    assert tikz.startswith("[x=1mm,y=1mm]") and r"\useasboundingbox" in tikz
    assert tikz.count(r"\draw[chartring]") == 4 and tikz.count(r"\draw[chartspoke]") == 3
    assert tikz.count(r"\node[chartkey]") == 3 and tikz.count(r"\node[chartnote,anchor=east]") == 2
    for key in "MNC":
        assert f"{{{key}}};" in tikz
    assert r"\fill[verdict-confirmed,radarfill]" in tikz and r"\draw[verdict-confirmed,radarline,solid]" in tikz
    assert r"\fill[verdict-proposed,radarfill]" in tikz and r"\draw[verdict-proposed,radarline,dashed]" in tikz
    x, y = radar_point(2, 3, RADAR_R)                  # the 1.0 value of the first series sits on the rim of axis C
    assert f"({x:.3f},{y:.3f}) circle" in tikz
    assert tikz.count("circle (0.700)") == 2 + 3       # markers only where a value is above zero
    assert all(COORD.fullmatch(part) for group in re.findall(r"\(([^()]*)\)", tikz) for part in group.split(","))
    assert r"\radarseriesrow{verdict-confirmed}{solid}{Confirmed findings}{confirmed packages}" in body
    assert r"\radarkeyrow{M}{Memory safety}{memory corruption}{Confirmed findings 0}" in body
    assert r"\chartcaption{1.0 is the largest axis.}" in body
    assert RADAR_LINE_STYLES == ("solid", "dashed", "dotted", "densely dashdotted")
    assert len({radar_line_style(index) for index in range(4)}) == 4 and radar_line_style(4) == "solid"


def test_hostile_text_is_escaped_and_rendering_is_deterministic() -> None:
    hostile = "x}\\write18{id}"
    chart = _chart(title=hostile, scale_note=hostile, axes=(RadarAxis(hostile, "M}"), AXES[1], AXES[2]),
                   series=(RadarSeries(hostile, "confirmed", (1.0, 0.0, 0.5), (hostile, "", "")),),
                   legend=(RadarLegendRow("axis", "M}", hostile, hostile), RadarLegendRow("series", hostile, hostile, hostile)))
    body = _body(_doc(chart))
    assert r"\write18" not in body and body.count(r"\textbackslash{}write18\{id\}") >= 6
    assert _body(_doc(chart)) == body


def test_all_zero_series_render_the_no_data_path_with_the_scale_note() -> None:
    body = _body(_doc(_chart(series=(RadarSeries("a", "neutral", (0.0, 0.0, 0.0)),))))
    assert r"\chartempty{No data}" in body and "tikzpicture" not in body and r"\radarkeyrow" not in body
    assert r"\chartcaption{1.0 is the largest axis.}" in body
