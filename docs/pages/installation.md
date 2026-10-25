# Installation

## Requirements

- Python **3.10 or later**. CI runs on 3.10 to 3.13.
- [`lief`](https://pypi.org/project/lief/) (0.15.1 or later), which pip
  installs automatically.

## From PyPI

The package is published on PyPI as **`reminder-detector`**:

```console
$ pip install reminder-detector
```

This installs the `reminder` Python package and the `reminder` console script.

## From source

```console
$ git clone https://github.com/packing-box/reminder
$ cd reminder
$ pip install .
```

For development, use an editable install:

```console
$ pip install -e .
```

## Checking the installation

```console
$ reminder --help
[...]
REMINDer 1.2.3
[...]
```

```python
>>> from reminder.__info__ import __version__
>>> __version__
'1.2.3'
```
