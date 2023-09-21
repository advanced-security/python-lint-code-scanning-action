"""Import the SarifFormatter class and get_flake8_rules function so they can be used by users of the package."""

__all__ = ["get_flake8_rules", "SarifFormatter"]

from .flake8_sarif_formatter import get_flake8_rules, SarifFormatter
