# Python Linting Action

> [!NOTE]
> This is an _unofficial_ tool created by Field Security Services, and is not officially supported by GitHub.

This Action and Python script lets you run one of several Python linters and type checkers, and upload the results to GitHub's Code Scanning, which is part of [Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) (free for open source projects hosted on GitHub).

## Supported linters and type checkers

- Linters:
  - [Flake8](https://flake8.pycqa.org/en/latest/)
  - [Pylint](https://www.pylint.org/)
  - [Ruff](https://beta.ruff.rs/)
  - [Fixit 2](https://fixit.readthedocs.io/en/stable/) - for Python 3.8 and above
- Type checkers:
  - [Mypy](https://mypy.readthedocs.io/en/stable/)
  - [Pytype](https://github.com/google/pytype/) - for Python 3.10 and below
  - [Pyright](https://github.com/microsoft/pyright)
  - [Pyre](https://pyre-check.org/)

## Requirements

- Python 3.8 or higher
- For Pytype, Python 3.10 or lower
- For Fixit, Python 3.8 or higher
- GitHub Actions
- GitHub Advanced Security (for private repositories)

## Usage

### Actions usage

#### Configure the linters

Configure the linters using a configuration file in your repository, appropriate to the linter.

Many can use `pyproject.toml`, but not all.

Example `pyproject.toml` and `.flake8` files for linting this repository are included.

#### Call the Action with a workflow

First check out the repository with `github/checkout` of a supported version, so the code is available to the workflow.

The simplest use is to use just one linter at a time:

```yaml
uses: advanced-security/python-lint-code-scanning-action@v1
with:
  linter: flake8
```

You can run it with more than one linter using a matrix:

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        linter: [flake8, pylint, ruff, mypy, pytype, pyright, fixit, pyre]
    steps:
      - uses: advanced-security/python-lint-code-scanning-action@v1
        with:
          linter: ${{ matrix.linter }}
```

Similarly, you can run it with more than one Python version:

```yaml
jobs:
  lint:

    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, 3.10, 3.11, 3.12]
    steps:
      - uses: advanced-security/python-lint-code-scanning-action@v1
        with:
          linter: flake8
          python-version: ${{ matrix.python-version }}
```

You could even combine both.

If you want to use plugins for one of the linters, you can install that before running the action, e.g.

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: python3 -m pip install flake8-bugbear
      - uses: advanced-security/python-lint-code-scanning-action@v1
        with:
          linter: flake8
```

Pin the version of a linter, e.g. if the latest version is incompatible with this Action.

> [!NOTE]
> Remember to put quotes around version strings so they are not interpreted as floating point numbers.

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: advanced-security/python-lint-code-scanning-action@v1
        with:
          linter: ruff
          ruff-version: "0.7.2"
```

### Command line usage

First install the Flake8 SARIF formatter, if you are using Flake8:

```bash
python3 -m pip install flake8-sarif-formatter
```

Then run the linter, which must already be installed in your environment:

```bash
python3 ./python_lint.py <linter> [<linter> ...] [<options>]
```

The linter/type checker can be one or more of `flake8`, `pylint`, `ruff`, `mypy`, `pytype`, `pyright`, `fixit`, `pyre`.

## FAQ

### Why not use existing Python linting Actions?

They don't all produce SARIF, and they don't upload to Code Scanning.

### Why not use MegaLinter or Super-linter?

They aggregate lots of linters, for a lot of languages, but do not focus on producing output in SARIF, nor on Python.

Although MegaLinter has a [SARIF output formatter](https://megalinter.io/latest/reporters/SarifReporter/), only those linters natively able to produce SARIF are usable this way.

This Action is specialised for useful linters for Python, and produces SARIF.

### Why not create N different Actions?

It's far more convenient to have one Action that can run all of the popular linters, so you can configure it once and then run it with different linters.

### Could you let me configure the linters using the Action's inputs?

No, because the configuration files are specific to each linter. Providing convenience abstractions over the inputs for all of the linters would be significantly more work than just using the configuration files.

It's possible that a future release might allow you to specify some very common shared options, such as line-length, but for now that's not been tackled.

### Why not add SARIF output directly to the linters, and then call them?

Good idea. That's something to consider for the future. For now it was quicker and easier to call the linters and process their output into SARIF, vs raising PRs against each linter.

### You really should provide some sensible defaults for the linters

Wow, so opinionated! We decided not to be opinionated 😁. Linting is very individual, and deciding on defaults beyond those of the tools themselves could prove to be a thankless task. Hopefully if you want to use these linters then you'll be able to configure them to your liking.

### What about tool X?

Lots of linters are wrapped up or replicated by these linters.

`pydocstyle` can be run using a plugin to Flake8, and `mccabe` is included in Flake8.

If there's one you really need that isn't runnable, please raise an issue or a PR to include it.

### Why can't I run all of the linters in one go?

Actions lets you do a matrix job, which does great work in parallelising things.

We could use Python multi-processing to run them all in parallel, but that doesn't make such sense on standard GitHub runners.

If you want to run them all at once you can call the underlying script with multiple linters, but that feature is really just to make testing easier, since they run in series.

### Why do I see an error, but the run is not marked as having failed?

This avoids errors with a single linter resulting in the whole run being marked as "in error". It is the Code Scanning results that are of interest, not whether every linter ran successfully.

You should check for errors in the Actions log and resolve them. It might be better to have an option to report failure if a linter does not run properly - raise an issue or a PR if you want that.

## License

This project is licensed under the terms of the MIT open source license. Please refer to the [LICENSE](LICENSE) for the full terms.

## Maintainers

See [CODEOWNERS](CODEOWNERS) for the list of maintainers.

## Support

> [!NOTE]
> This is an _unofficial_ tool created by Field Security Services, and is not officially supported by GitHub.

See the [SUPPORT](SUPPORT.md) file.

## Background

See the [CHANGELOG](CHANGELOG.md), [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [SUPPORT](SUPPORT.md), [CODE OF CONDUCT](CODE_OF_CONDUCT.md) and [PRIVACY](PRIVACY.md) files for more information.
