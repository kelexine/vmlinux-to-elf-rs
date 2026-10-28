# Embedded kernel database

`kernel_db.sqlite3.xz` is the upstream project's `kernel_db/database.sqlite3`
(marin-m/vmlinux-to-elf, shipped in the PyPI release 1.4.0), recompressed with
xz so it can live in git and inside the binary.

| | size | sha256 |
|---|---|---|
| `database.sqlite3` (decompressed) | 34,234,368 bytes | `580fff8b0746fd815fccc890f87ac424fbc32b7dd66b2134cb8ca723e53b372d` |
| `kernel_db.sqlite3.xz` (this file) | 1,783,284 bytes | `a4c48239d381e37c335e30229920a547d36ec39aa3780658d5aecb8a54ff35c3` |

Contents: known architectures, ELF machine values, 947 kernel versions with
release dates and source URLs, ~139k per-version "interesting files", and the
Debian release table used to suggest a build environment. It affects log
output only; it never changes the generated ELF.

Licensed under GPL-3.0-or-later, like the upstream project it comes from.

## Regenerate

```sh
xz -9e --keep --stdout database.sqlite3 > kernel_db.sqlite3.xz
```

(or Python's `lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)`).
The decoder verifies the xz CRC64, so a corrupted asset is detected at
extraction time.
