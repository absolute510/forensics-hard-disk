# pyforensics

A small command-line file recovery tool for raw disk devices/images.

It supports two recovery modes:

- **Deep recovery (`dr`)** — scans a raw device or disk image byte-by-byte
  for known file signatures (magic headers/footers) and carves out matching
  files. Useful on formatted or repartitioned devices where filesystem
  metadata is gone but the file content may still be intact.
- **Quick recovery (`qr`)** — recovers specific deleted files by inode,
  using [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) (`fls`,
  `istat`, `icat`). Useful when the filesystem metadata is still present
  (e.g. recently deleted files).

## Requirements

- Python 3
- For quick recovery (`qr`) only: [The Sleuth Kit](https://www.sleuthkit.org/)
  installed and on your `PATH` (provides `fls`, `istat`, `icat`)
- Read access to the target raw device or disk image (on Linux/macOS this
  usually means running as root / with `sudo`)

## Usage

```
python pyforensics.py <action> <device> [options]
```

| Argument | Description |
|---|---|
| `action` | `dr` for deep recovery, `qr` for quick recovery |
| `device` | Path to the device or image file, e.g. `/dev/sda` or `disk.img` |

### Options

| Flag | Description |
|---|---|
| `-f`, `--file_types` | Comma-separated file types to scan for in deep recovery (e.g. `jpg,png,pdf`). Default: `jpg` |
| `-o`, `--output_path` | Directory to write recovered files to. Created automatically if missing. Default: `recovered` |
| `-i`, `--inodes` | Inode(s) for quick recovery, e.g. `12341:photo.jpg,12342:report.pdf`. If omitted, `qr` lists deleted files interactively |
| `-v`, `--version` | Print the tool's version and exit |

### Supported file types (deep recovery)

`jpg`, `png`, `pdf`, `exe`, `dll`, `rdl`, `bat`, `docx`, `xls`, `doc`, `psd`,
`mp3`, `wav`, `mp4`

## Examples

### Deep recovery

Scan a raw device for JPEG images (default file type) and write results to
`./recovered/`:

```bash
sudo python pyforensics.py dr /dev/sda
```

Scan a disk image for JPEGs, PNGs and PDFs, writing output to a custom
folder:

```bash
python pyforensics.py dr disk.img -f jpg,png,pdf -o ./out
```

Recovered files are named `<n>.<ext>` (e.g. `0.jpg`, `1.pdf`, ...) in the
output directory, numbered in the order they were found.

### Quick recovery

List deleted files on a device/image and recover one interactively:

```bash
sudo python pyforensics.py qr /dev/sda1
```

This prints the output of `fls -r`, then prompts for an inode number and a
filename to save the recovered content as.

Recover specific inodes directly, without the interactive prompt:

```bash
sudo python pyforensics.py qr /dev/sda1 -i 12341:photo.jpg,12342:report.pdf -o ./out
```

## Notes

- Deep recovery relies on recognizing file signatures and, for some types,
  a trailing size limit instead of a true end marker — recovered files are
  not guaranteed to be complete or valid, especially for fragmented files.
- Run against a **copy/image** of the device whenever possible rather than
  the live device, to avoid further overwriting recoverable data.
- `qr` executes external Sleuth Kit binaries (`fls`, `istat`, `icat`) found
  on your `PATH`.
