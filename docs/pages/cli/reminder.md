# `reminder`: detect packing

`reminder` applies the [entropy heuristic](../internals.md) to one executable
and prints whether it is packed.

```console
$ reminder [--entropy-threshold ENTROPY_THRESHOLD] [-b] [-h] [-v] path
```

## Arguments

| Argument | Description |
|---|---|
| `path` | The executable to analyze (PE, ELF or Mach-O). It must exist. |

### Optional arguments

| Option | Default | Description |
|---|---|---|
| `--entropy-threshold T` | 6.85 | Report the file as packed when the entropy of its writable entry point section is above `T`. `T` is a non-negative number, in bits per byte (0 to 8). |

### Extra arguments

| Option | Description |
|---|---|
| `-b`, `--benchmark` | Print the elapsed time, in seconds, after the result. |
| `-v`, `--verbose` | Show debug information: the entry point and its section, whether the section is writable, and its entropy. |
| `-h`, `--help` | Show the help message and exit. |

## Output

`reminder` prints one of:

| Output | Meaning |
|---|---|
| `True` | The executable is packed. |
| `False` | The executable is not packed. |
| `?` | The executable could not be analyzed, for instance because it is not a supported executable or its entry point could not be found. An error message is logged before. |

```console
$ reminder -v calc_packed.exe
DEBUG:reminder:EP at 0x0003c380 in UPX1
DEBUG:reminder:UPX1 is writable
DEBUG:reminder:entropy = 7.909 (threshold: 6.850)
True
$ reminder -v /bin/ls
DEBUG:reminder:EP at 0x00006d30 in .text
False
$ reminder /etc/passwd
ERROR:reminder:/etc/passwd is not an executable
?
```

With `-b`, the elapsed time is printed on a second line:

```console
$ reminder calc_packed.exe -b
True
0.000830580000183545
```

## Exit code

| Code | Meaning |
|---|---|
| `0` | The analysis ran, whatever the result (including `?`). |
| `1` | An unexpected error occurred. |
| `2` | Invalid arguments. |

!!! note
    The exit code does not tell whether the file is packed. Parse the output,
    or use the [Python API](../api.md), for that.

## Examples

```console
$ reminder program.exe
$ reminder /bin/ls --entropy-threshold 6.9
$ reminder program.exe -b -v
```
