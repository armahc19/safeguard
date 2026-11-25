import pytest

from app.core.exceptions import ValidationFailed
from app.core.phone import normalize_phone


@pytest.mark.parametrize("raw, expected", [
    ("0241234567", "+233241234567"),
    ("024 123 4567", "+233241234567"),
    ("+233241234567", "+233241234567"),
    ("233241234567", "+233241234567"),
    ("00233241234567", "+233241234567"),
    ("+1 (415) 555-0132", "+14155550132"),
])
def test_valid(raw, expected):
    assert normalize_phone(raw) == expected


@pytest.mark.parametrize("raw", ["", "abc", "12345", "+0123456789", "+23324123456789012345", "5551234567"])
def test_invalid(raw):
    with pytest.raises(ValidationFailed):
        normalize_phone(raw)
