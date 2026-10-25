# Contributing

Contributions are welcome, especially **tuned thresholds for ELF and Mach-O**
and **false positive or false negative reports**.

## Reporting issues

Open an issue on [GitHub](https://github.com/packing-box/reminder/issues)
and include:

- the REMINDer and LIEF versions (`reminder --help` prints the former,
  `python -c "import lief; print(lief.__version__)"` the latter);
- the exact command and its output, ideally with `-v`;
- if possible, a link to (or the hash of) the sample.

## Security

Please do **not** report vulnerabilities in public issues. See the
[security policy](https://github.com/packing-box/reminder/blob/main/SECURITY.md):
report them privately through the repository's *Security* tab
(*Report a vulnerability*).

Dependencies are monitored by Dependabot and audited with
[pip-audit](https://github.com/pypa/pip-audit) by the `security` workflow
(`.github/workflows/security.yml`), on every push and pull request to `main`
and weekly.

## Tuning thresholds

The default thresholds are in the `THRESHOLDS` dictionary of
`src/reminder/__init__.py` (see [Thresholds](internals.md#thresholds)). Test
any change on packed and unpacked samples. The
[packed PE dataset](https://github.com/packing-box/dataset-packed-pe),
[packed ELF dataset](https://github.com/packing-box/dataset-packed-elf) and
[Docker Packing Box](https://github.com/packing-box/docker-packing-box) help
with this.

## Development setup

```console
$ git clone https://github.com/packing-box/reminder
$ cd reminder
$ pip install -e .
$ pip install flake8
$ flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

CI (`.github/workflows/python-package.yml`) installs the package on Python
3.10 to 3.13 and runs this flake8 check.

## Releasing

The version is stored in `src/reminder/VERSION.txt`. When a push to `main`
changes that file, CI builds the package and publishes it to PyPI.

## Building this documentation

```console
$ pip install -r docs/requirements.txt
$ mkdocs serve -f docs/mkdocs.yml          # live preview at http://127.0.0.1:8000
$ mkdocs build --strict -f docs/mkdocs.yml # what Read the Docs runs
```

Read the Docs builds the site from `.readthedocs.yaml` at the root of the
repository.
