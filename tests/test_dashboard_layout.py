from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src" / "rocks" / "dashboard" / "templates"
STYLES = ROOT / "src" / "rocks" / "dashboard" / "static"


def test_overflow_styles_cover_long_content_and_common_mobile_widths():
    stylesheet = (STYLES / "dashboard-overflow.css").read_text(encoding="utf-8")

    assert "overflow-wrap: anywhere" in stylesheet
    assert "min-width: 0" in stylesheet
    assert "overflow-x: auto" in stylesheet
    assert "@media (max-width: 768px)" in stylesheet
    assert "@media (max-width: 480px)" in stylesheet


def test_wide_dashboard_tables_use_contained_scroll_regions():
    expected_tables = {
        "dashboard.html": 1,
        "edges.html": 1,
        "telemetry.html": 1,
        "alerts.html": 1,
        "events.html": 1,
        "telemetry_context.html": 2,
    }
    for name, expected_count in expected_tables.items():
        template = (TEMPLATES / name).read_text(encoding="utf-8")
        assert 'href="/dashboard/static/dashboard-overflow.css"' in template
        assert template.count('class="table-scroll"') == expected_count
        assert template.count("<table") == expected_count


def test_all_dashboard_views_have_mobile_viewport_and_overflow_styles():
    for template_path in TEMPLATES.glob("*.html"):
        template = template_path.read_text(encoding="utf-8")
        assert 'name="viewport"' in template, template_path.name
        assert 'href="/dashboard/static/dashboard-overflow.css"' in template, template_path.name
