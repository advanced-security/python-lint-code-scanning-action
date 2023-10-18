#!/usr/bin/env python3

"""
Lint Python files using your choice of linter or type checker.

Get output in SARIF, for upload to GitHub Code Scanning.

Written by Field Services, GitHub

Copyright (c) GitHub, 2023
"""

import sys
import os
import logging
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run
import json
from typing import Optional, Any, List, Dict
import re


LOG = logging.getLogger(__name__)


REMOVE_QUOTATIONS = re.compile(r'"[^"]*"')
REMOVE_NUMBERS = re.compile(r"\d+")
MYPY_TO_SARIF_LEVELS = {"error": "error", "warning": "warning", "note": "note"}
REMOVE_REPORT_PREIX = re.compile(r"^report")
FIND_CAMEL_CASE = re.compile("[A-Z][^A-Z]+")
REMOVE_TRAILING_SQUARE_BRACKETS = re.compile(r"\s*\[[^\]]+\]\s*$")
REMOVE_HINT = re.compile(r"\s*\(hint: [^)]+\)\s*$")

# pytype is only supported on Python 3.10 and below, at the time of writing
# the rest of the script is Python 3.7+
if sys.version_info[0] == 2 or (sys.version_info[0] == 3 and sys.version_info[1] < 7):
    logging.basicConfig(level=logging.INFO)
    LOG.error("This script requires Python 3.7 or above")
    sys.exit(1)


def make_sarif_run(tool_name: str) -> dict:
    """Template for a SARIF run."""
    sarif_run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "rules": [],
            }
        },
        "results": [],
    }

    return sarif_run


def flake8_linter(target: Path, *_args) -> None:
    """Run the flake8 linter.

    In contrast to the other linters, flake8 has plugin architecture.

    We rely on the 'sarif' formatter being installed, which is part of this package.
    """
    process = run(["flake8", target, "--format", "sarif"], capture_output=True, check=False)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from flake8")
        return None

    try:
        sarif = json.loads(process.stdout.decode("utf-8"))
    except json.JSONDecodeError as err:
        LOG.error("Unable to parse flake8 output: %s", err)
        LOG.debug("Output: %s", process.stdout.decode("utf-8"))
        return None

    if "runs" in sarif and len(sarif["runs"]) > 0:
        return sarif["runs"][0]

    LOG.error("SARIF not correctly formed, or no runs to output")
    return None


def ruff_format_sarif(results: List[Dict[str, Any]], target: Path) -> dict:
    """Convert Ruff output into SARIF."""
    sarif_run = make_sarif_run("Ruff")

    from flake8_sarif_formatter import flake8_sarif_formatter

    flake8_rules = flake8_sarif_formatter.get_flake8_rules()

    for result in results:
        code = result["code"]
        rule_id = f"ruff/{code}"
        filename = result["filename"]
        message = result["message"]

        location: Dict[str, int] = result["location"]
        end_location: Dict[str, int] = result["end_location"]

        start_line = location["row"]
        start_column = location["column"]
        end_line = end_location["row"]
        end_column = end_location["column"]

        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(str(filename)).resolve().absolute().relative_to(target).as_posix(),
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endLine": end_line,
                            "endColumn": end_column,
                        },
                    }
                }
            ],
            # TODO: think about how to add "fix" into the SARIF
            # Code Scanning doesn't do anything with it, so it isn't a high priority
        }

        sarif_run["results"].append(sarif_result)

        # append rule ID and label to the SARIF
        rules = sarif_run["tool"]["driver"]["rules"]

        if rule_id not in [rule["id"] for rule in rules]:
            short_description = flake8_rules[code].get("message", code) if code in flake8_rules else code

            # TODO: when Code Scanning supports it, add "content" as longDescription

            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": short_description,
                },
            }

            rules.append(sarif_rule)

    return sarif_run


def ruff_linter(target: Path, *_args) -> Optional[dict]:
    """Run the ruff linter."""
    try:
        # pylint: disable=import-outside-toplevel
        from ruff import __main__ as ruff

    # pylint: enable=import-outside-toplevel
    except ImportError:
        LOG.error("Unable to import ruff")
        return None

    try:
        ruff_exe = ruff.find_ruff_bin()
    except AttributeError:
        ruff_exe = "ruff" if sys.platform != "win32" else "ruff.exe"

    # call ruff, capture STDOUT and STDERR using subprocess
    process = run([ruff_exe, target, "--output-format", "json"], capture_output=True, check=False)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from ruff")
        return None

    try:
        results = json.loads(process.stdout.decode("utf-8"))
    except json.JSONDecodeError as err:
        LOG.error("Unable to parse ruff output: %s", err)
        LOG.debug("Output: %s", process.stdout.decode("utf-8"))
        return None

    # format the ruff JSON into SARIF
    sarif_run = ruff_format_sarif(results, target)

    return sarif_run


def make_pylint_description(message: str) -> str:
    """Format 'message-id-form' into 'Message id form'."""
    message = message.replace("-", " ")
    message = message.capitalize()
    return message


def pylint_format_sarif(results: List[Dict[str, Any]], target: Path) -> dict:
    """Convert Pylint output into SARIF."""
    sarif_run = make_sarif_run("Pylint")

    for result in results:
        rule_id = f'pylint/{result["message-id"]}'
        message = result["message"]
        description = make_pylint_description(result["symbol"])
        filename = target.joinpath(str(result["path"])).resolve().absolute().relative_to(target).as_posix()
        start_line = int(result["line"])
        start_column = int(result["column"]) + 1
        end_line = int(result["endLine"]) if result["endLine"] is not None else int(result["line"])
        end_column = int(result["endColumn"]) + 1 if result["endColumn"] is not None else int(result["column"]) + 1

        # append result to SARIF
        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": filename,
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endLine": end_line,
                            "endColumn": end_column,
                        },
                    }
                }
            ],
        }

        sarif_run["results"].append(sarif_result)

        # append rule ID and label to the SARIF
        rules = sarif_run["tool"]["driver"]["rules"]

        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": description,
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def pylint_linter(target: Path, *_args) -> Optional[dict]:
    """Run the pylint linter."""
    process = run(
        ["pylint", "--output-format=json", "--recursive=y", target.absolute().as_posix()],
        capture_output=True,
        check=False,
    )

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pylint")
        return None

    try:
        results = json.loads(process.stdout.decode("utf-8"))
    except json.JSONDecodeError as err:
        LOG.error("Unable to parse pylint output: %s", err)
        LOG.debug("Output: %s", process.stdout.decode("utf-8"))
        return None

    # format the pylint JSON into SARIF
    sarif_run = pylint_format_sarif(results, target)

    return sarif_run


def mypy_format_sarif(mypy_results: str, target: Path) -> dict:
    """Convert MyPy output into SARIF."""
    sarif_run = make_sarif_run("MyPy")

    for result in mypy_results.split("\n"):
        if not result:
            continue

        if ":" not in result:
            LOG.debug("Skipping line, no location found: %s", result)
            continue

        # NOTE: assumes no filename contains " :", may need to be addressed if that causes issues
        location, message = result.split(": ", 1)

        # NOTE: assumes we're using `--show-error-end`, which gives the end line/column too
        try:
            filename, start_line, start_column, end_line, end_column, *_ = location.split(":") + [1, None, None, None]
        except ValueError as err:
            LOG.error("Unable to parse location %s: %s", location, err)
            continue

        if filename is None or start_line is None or start_column is None:
            LOG.error("Unable to parse location, missing filename or start line/column: %s", location)
            continue

        if ": " not in message:
            LOG.debug("Skipping line, no message found: %s", result)
            continue

        level, rule_msg = message.split(": ", 1)

        if " [" in rule_msg:
            rule_text, rule_id = rule_msg.split("  [", 1)
            rule_id = rule_id.rstrip("]")
            rule_id = f"mypy/{rule_id}"

            rule_text = REMOVE_QUOTATIONS.sub('"..."', rule_text)
            rule_text = REMOVE_NUMBERS.sub("N", rule_text)
            rule_text = REMOVE_TRAILING_SQUARE_BRACKETS.sub("", rule_text)
            rule_text = REMOVE_HINT.sub("", rule_text)
        else:
            LOG.debug("Skipping line, no MyPy rule id found: %s", result)
            continue

        sarif_level = MYPY_TO_SARIF_LEVELS.get(level, "note")

        sarif_result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": rule_msg,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(str(filename)).resolve().relative_to(target).as_posix(),
                        },
                        "region": {
                            "startLine": int(start_line),
                            "startColumn": int(start_column),
                            "endLine": int(end_line) if end_line is not None else start_line,
                            "endColumn": int(end_column) if end_column is not None else start_column,
                        },
                    }
                }
            ],
        }

        sarif_run["results"].append(sarif_result)

        # append the rule if we haven't already recorded it in the rules array
        rules = sarif_run["tool"]["driver"]["rules"]
        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": rule_text,
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def mypy_linter(target: Path, typeshed_path: Path) -> Optional[dict]:
    """Run the mypy linter."""
    mypy_args = [
        "--install-types",
        "--non-interactive",
        "--ignore-missing-imports",
        "--no-error-summary",
        "--no-pretty",
        "--show-error-codes",
        "--show-column-numbers",
        "--show-error-end",
        "--show-absolute-path",
        "--custom-typeshed-dir",
        typeshed_path.as_posix(),
    ]

    process_lint = run(["mypy", *mypy_args, target.absolute().as_posix()], capture_output=True, check=False)

    # if process_lint.stderr:
    #     LOG.error("STDERR: %s", process_lint.stderr.decode("utf-8"))
    #     return None

    # if not process_lint.stdout:
    #     return None

    sarif_run = mypy_format_sarif(process_lint.stderr.decode("utf-8"), target)

    return sarif_run


def make_pyright_description(rule: str) -> str:
    """Format 'reportSomeRuleDescription' into 'Some rule description'."""
    rule = REMOVE_REPORT_PREIX.sub("", rule)
    rule = FIND_CAMEL_CASE.sub(lambda x: x.group(0).lower() + " ", rule)
    rule = rule.capitalize()

    return rule


def pyright_format_sarif(results: dict, target: Path) -> dict:
    """Convert Pyright output into SARIF."""
    sarif_run = make_sarif_run("Pyright")

    for diagnostic in results["generalDiagnostics"]:
        filename = diagnostic["file"]
        message = diagnostic["message"]
        rule_id = f'pyright/{diagnostic["rule"]}' if "rule" in diagnostic else "pyright/builtIn"
        description = make_pyright_description(diagnostic["rule"] if "rule" in diagnostic else "builtIn")

        start_line = diagnostic["range"]["start"]["line"] + 1
        start_column = diagnostic["range"]["start"]["character"] + 1
        end_line = diagnostic["range"]["end"]["line"] + 1
        end_column = diagnostic["range"]["end"]["character"] + 1

        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(filename).resolve().relative_to(target).as_posix(),
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endLine": end_line,
                            "endColumn": end_column,
                        },
                    }
                }
            ],
        }

        sarif_run["results"].append(sarif_result)

        # append the rule if we haven't already recorded it in the rules array
        rules = sarif_run["tool"]["driver"]["rules"]
        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": description,
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def pyright_linter(target: Path, typeshed_path: Path) -> Optional[dict]:
    """Run the pyright linter."""
    process = run(
        ["pyright", "--outputjson", "--typeshedpath", typeshed_path, target.absolute().as_posix()],
        capture_output=True,
        check=False,
    )

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pyright")
        return None

    try:
        results = json.loads(process.stdout.decode("utf-8"))
    except json.JSONDecodeError as err:
        LOG.error("Unable to parse pyright output: %s", err)
        LOG.debug("Output: %s", process.stdout.decode("utf-8"))
        return None

    # format the pyright JSON into SARIF
    sarif_run = pyright_format_sarif(results, target)

    return sarif_run


def pytype_format_sarif(results: str, target: Path) -> dict:
    """Convert PyType output into SARIF."""

    sarif_run = make_sarif_run("Pytype")

    pytype_re = re.compile(
        r'File "(?P<filename>[^"]+)", line (?P<line>\d+), in (?P<scope>\S+): (?P<message>.*) \[(?P<rule>[a-z-]+)\]'
    )

    for line in results.split("\n"):
        match = pytype_re.search(line)
        if match:
            filename = match.group("filename")
            line_number = int(match.group("line"))
            message = match.group("message")
            rule = match.group("rule")

            rule_id = f"pytype/{rule}"

            sarif_result = {
                "ruleId": rule_id,
                "level": "note",
                "message": {
                    "text": message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": Path(filename).resolve().relative_to(target).as_posix(),
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": 1,
                                "endLine": line_number,
                                "endColumn": 1,
                            },
                        }
                    }
                ],
            }

            sarif_run["results"].append(sarif_result)

            # append the rule if we haven't already recorded it in the rules array
            rules = sarif_run["tool"]["driver"]["rules"]
            if rule_id not in [rule["id"] for rule in rules]:
                sarif_rule = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": make_pylint_description(rule),
                    },
                }
                rules.append(sarif_rule)

    return sarif_run


def pytype_linter(target: Path, typeshed_path: Path) -> Optional[dict]:
    """Run the pytype linter."""
    os.environ["TYPESHED_HOME"] = typeshed_path.as_posix()

    process = run(
        ["pytype", "--exclude", ".pytype/", "--", target.as_posix()],
        capture_output=True,
        check=False,
    )

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pytype")
        return None

    # process STDOUT
    results = process.stdout.decode("utf-8")

    sarif_run = pytype_format_sarif(results, target)

    return sarif_run


def pyre_linter(target: Path, typeshed_path: Path) -> Optional[dict]:
    """Run the pytype linter."""
    process = run(
        [
            "pyre",
            "--source-directory",
            target.as_posix(),
            "--output",
            "sarif",
            "--typeshed",
            typeshed_path.as_posix(),
            "check",
        ],
        capture_output=True,
        check=False,
    )

    if process.stderr:
        LOG.debug("STDERR: %s", process.stderr.decode("utf-8"))

    if not process.stdout:
        LOG.error("No output from pytype")
        return None

    try:
        sarif = json.loads(process.stdout.decode("utf-8"))
    except json.JSONDecodeError as err:
        LOG.error("Unable to parse pyre output: %s", err)
        LOG.debug("Output: %s", process.stdout.decode("utf-8"))
        return None

    if "runs" in sarif and len(sarif["runs"]) > 0:
        return sarif["runs"][0]

    LOG.error("SARIF not correctly formed, or no runs to output")
    return None


def make_fixit_description(rule: str) -> str:
    """Format 'SomeRuleDescription' into 'Some rule description'."""
    rule = FIND_CAMEL_CASE.sub(lambda x: x.group(0).lower() + " ", rule)
    rule = rule.capitalize()
    return rule


def fixit_format_sarif(results: str, target: Path) -> dict:
    """Convert fixit output into SARIF."""
    sarif_run = make_sarif_run("Fixit")

    fixit_re = re.compile(r"^(?P<filename>[^@]+)@(?P<line>\d+):(?P<column>\d+) (?P<rule>[A-Za-z]+): (?P<message>.*)$")

    for line in results.split("\n"):
        match = fixit_re.search(line)
        if match:
            filename = match.group("filename")
            line_number = int(match.group("line"))
            column = int(match.group("column"))
            message = match.group("message")
            rule = match.group("rule")
            description = make_fixit_description(rule)

            rule_id = f"fixit/{rule}"

            sarif_result = {
                "ruleId": rule_id,
                "level": "note",
                "message": {
                    "text": message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": Path(filename).resolve().relative_to(target).as_posix(),
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": column,
                                "endLine": line_number,
                                "endColumn": column,
                            },
                        }
                    }
                ],
            }

            sarif_run["results"].append(sarif_result)

            # append the rule if we haven't already recorded it in the rules array
            rules = sarif_run["tool"]["driver"]["rules"]
            if rule_id not in [rule["id"] for rule in rules]:
                sarif_rule = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": description,
                    },
                }
                rules.append(sarif_rule)

    return sarif_run


def fixit_linter(target: Path, *_args) -> Optional[dict]:
    """Run the fixit linter, from Meta."""
    process = run(["fixit", "lint", target.absolute().as_posix()], capture_output=True, check=False)

    if process.returncode > 1:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.debug("No output from fixit")
        return None

    # process STDOUT
    results = process.stdout.decode("utf-8")

    sarif_run = fixit_format_sarif(results, target)

    return sarif_run


def make_paths_relative_to_target(runs: List[dict], target: Path) -> None:
    """Make all paths relative to the target."""
    for sarif_run in runs:
        for result in sarif_run["results"]:
            for location in result["locations"]:
                uri = Path(location["physicalLocation"]["artifactLocation"]["uri"])
                if uri.is_absolute():
                    location["physicalLocation"]["artifactLocation"]["uri"] = (
                        uri.resolve().relative_to(target).as_posix()
                    )


def fix_sarif_locations(runs: List[dict]) -> None:
    """Fix the SARIF locations.
    
    Normalise values less than 1 to 1, e.g. -1 or 0.
    
    Convert strings to ints.

    For anything that can't be converted to an int, set it to 1.
    """
    for sarif_run in runs:
        for result in sarif_run["results"]:
            for location in result["locations"]:
                region = location["physicalLocation"]["region"]
                for key in ("startLine", "endLine", "startColumn", "endColumn"):
                    if key in region:
                        try:
                            region[key] = int(region[key])
                        except ValueError:
                            LOG.error("Unable to convert %s to int", region[key])
                            region[key] = 1
                            continue
                        if region[key] < 1:
                            region[key] = 1


LINTERS = {
    "pylint": pylint_linter,
    "ruff": ruff_linter,
    "flake8": flake8_linter,
    "mypy": mypy_linter,
    "pyright": pyright_linter,
    "fixit": fixit_linter,
    "pyre": pyre_linter,
}

# pytype is only supported on Python 3.10 and below, at the time of writing
if sys.version_info[0] == 3 and sys.version_info[1] <= 10:
    LINTERS["pytype"] = pytype_linter


def add_args(parser: ArgumentParser) -> None:
    """Add arguments to the parser."""
    parser.add_argument("linter", choices=LINTERS.keys(), nargs="+", help="The linter(s) to use")
    parser.add_argument("--target", "-t", default=".", required=False, help="Target path for the linter")
    parser.add_argument("--output", "-o", default="python_linter.sarif", required=False, help="Output filename")
    parser.add_argument("--typeshed-path", required=False, help="Path to typeshed")
    parser.add_argument("--debug", "-d", action="store_true", required=False, help="Enable debug logging")


def main() -> None:
    """Main entry point for the application."""
    parser = ArgumentParser(description="__description__")
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    if any({linter not in LINTERS for linter in args.linter}):
        LOG.error("Invalid linter choice: %s", args.linter)
        sys.exit(1)

    sarif_runs: List[dict] = []

    target = Path(args.target).resolve().absolute()
    typeshed_path = Path(args.typeshed_path).resolve().absolute() if args.typeshed_path is not None else None

    for linter in args.linter:
        LOG.debug("Running %s", linter)

        sarif_run = LINTERS[linter](target, typeshed_path)

        if sarif_run is not None:
            sarif_runs.append(sarif_run)

    if len(sarif_runs) == 0:
        LOG.info("No SARIF runs to output")
        sys.exit(0)

    make_paths_relative_to_target(sarif_runs, target)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": sarif_runs,
    }

    # output SARIF
    with open(f"{args.output}", "w", encoding="utf-8") as sarif_file:
        json.dump(sarif, sarif_file, indent=2)


if __name__ == "__main__":
    main()
