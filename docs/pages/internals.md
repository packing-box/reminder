# How it works

## Overview

```text
                                          ┌──────────── no section ──────────▶ True
 program.exe ─LIEF─▶ entry point ─▶ EP section
                                          └─ writable? ─ no ─────────────────▶ False
                                                 │
                                                yes
                                                 │
                                          entropy > threshold? ─ yes ────────▶ True
                                                 │
                                                 no ─────────────────────────▶ False
```

The heuristic comes from Han et al.,
[*Packed PE File Detection for Malware Forensics*](https://ieeexplore.ieee.org/document/5404211).
Packers usually write the unpacked code at run time into the section where
execution starts, so that section must be writable. And as it holds
compressed or encrypted data, its entropy is high. A regular executable
starts in a read-only code section.

1. Parse the executable with [LIEF](https://github.com/lief-project/LIEF) and
   find the entry point (EP) and the section holding it.
2. If there is no such section, the executable is **packed**.
3. If the section is not writable, the executable is **not packed**.
4. Otherwise, it is **packed** if the entropy of the section is above the
   threshold, and **not packed** if not.

## Entry point section per format

| Format | Entry point | Section | Writable when |
|---|---|---|---|
| PE | `AddressOfEntryPoint` (RVA) | The section holding the RVA | The section has `IMAGE_SCN_MEM_WRITE` |
| ELF | `e_entry`, converted to a file offset | The section holding the offset | The section has `SHF_WRITE` |
| Mach-O | `LC_MAIN` / `LC_UNIXTHREAD` entry point, converted to a file offset | The section holding the offset | Its segment's initial protection includes `VM_PROT_WRITE` |

Mach-O sections have no permissions of their own: they inherit them from the
segment that contains them.

### No entry point section

Some packers also pack the section header table. For instance, ELF files
packed with UPX have no sections for LIEF. When no section holds the entry
point, the executable is considered **packed**.

## Thresholds

The entropy is the Shannon entropy of the section content, in bits per byte
(0 to 8), as computed by LIEF.

| Format | Default threshold |
|---|---|
| PE | 6.85 |
| ELF, Mach-O | 6.85 (the PE value, not tuned yet) |

The thresholds are in the `THRESHOLDS` dictionary of the `reminder`
package. `--entropy-threshold` (or `entropy_threshold` in the API) overrides
them.

## Limitations

- Only the entry point section is inspected. Packers that unpack into a
  separate, newly allocated region or keep the entry point in a read-only
  stub section are not detected (on ELF, for instance, Ezuri, Midgetpack
  and Ward).
- Mach-O files packed with UPX keep their entry point in a read-only
  `upxTEXT` section, so they are not detected.
- Scripts and other non-native wrappers (for instance gzexe on Linux) are not
  executables for LIEF: the result is `?`.
