"""Format Flake8 output as SARIF."""

import sys
import json
from pathlib import Path
from typing import List, Dict
from flake8.formatting import base
from flake8.style_guide import Violation
import requests
from bs4 import BeautifulSoup


class SarifFormatter(base.BaseFormatter):
    """SARIF formatter for Flake8."""

    def after_init(self):
        """Initialize the SARIF."""
        self.sarif_results = []
        self.sarif_rules = []
        self.rules = self.get_flake8_rules()

    def get_flake8_rules(self):
        """Get the Flake8 rules.
        
        Download from https://www.flake8rules.com/api/rules.json,
        or get from ./data/rules.json if that doesn't work.
        """
        rules: List[Dict[str, str]] = []

        try:
            rules = requests.get("https://www.flake8rules.com/api/rules.json").json()
        except Exception:
            with open(Path(__file__).parent / "data/rules.json", "r", encoding="utf-8") as f:
                rules = json.load(f)

        rules_dict: Dict[str, Dict[str, str]] = {}

        for rule in rules:
            if "content" in rule:
                # HTML to plain text
                rule["content"] = "".join(
                    BeautifulSoup(rule["content"], features="html.parser").findAll(text=True)
                )
            rules_dict[rule["code"]] = rule

        return rules_dict

    def stop(self):
        """Output the SARIF."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "Flake8", "rules": self.sarif_rules},
                    },
                    "results": self.sarif_results,
                }
            ],
        }

        json.dump(sarif, self.output_fd if self.output_fd is not None else sys.stdout, indent=2)

    def handle(self, error: Violation):
        """Convert the error into a SARIF result, and append it to the SARIF."""
        rule_id = f"flake8/{error.code}"

        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": error.text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(error.filename).resolve().absolute().as_uri(),
                        },
                        "region": {
                            "startLine": error.line_number,
                            "startColumn": error.column_number,
                            "endLine": error.line_number,
                            "endColumn": error.column_number,
                        },
                    }
                }
            ],
        }

        self.sarif_results.append(sarif_result)

        if rule_id not in [rule["id"] for rule in self.sarif_rules]:
            short_description = self.rules[error.code].get("message", error.code) if error.code in self.rules else error.code
            long_description = self.rules[error.code].get("content", error.code) if error.code in self.rules else error.code

            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": short_description,
                },
                "longDescription": {
                    "content": long_description,
                },
            }

            self.sarif_rules.append(sarif_rule)
