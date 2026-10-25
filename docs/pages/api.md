# Python API

The `reminder` package exposes one class:

```python
from reminder import REMINDer
```

---

## `REMINDer`

```python
REMINDer(entropy_threshold=None, logger=None, **kwargs)
```

Configures a detector. One instance can analyze many files.

| Parameter | Type | Description |
|---|---|---|
| `entropy_threshold` | `float` or `None` | Entropy threshold, in bits per byte. `None` uses the default threshold of the executable format (see [Thresholds](internals.md#thresholds)). |
| `logger` | `logging.Logger` | Optional logger. When set, errors are logged and `detect` returns `"?"`. Otherwise, errors raise exceptions. |
| `**kwargs` | | Ignored. It lets you pass `vars(args)` from an argument parser. |

### `detect`

```python
REMINDer.detect(executable)
```

Analyzes one executable.

| Parameter | Type | Description |
|---|---|---|
| `executable` | `str` or path-like | Path to the executable. |

**Returns**:

- `True` if the executable is packed;
- `False` if it is not;
- `"?"` if it could not be analyzed (only when a `logger` is set).

**Raises**, when no `logger` is set:

- `TypeError` if LIEF cannot parse the file as an executable;
- `OSError` if the executable format is not supported;
- `RuntimeError` if the entry point or its section could not be computed.

## Example

```python
import logging
from reminder import REMINDer

detector = REMINDer(entropy_threshold=6.9, logger=logging.getLogger("reminder"))

for path in ["a.exe", "/bin/ls", "not-an-executable.txt"]:
    print(path, detector.detect(path))
```
