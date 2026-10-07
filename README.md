# pyforensics

A small command-line file recovery tool for raw disk devices/images.

It supports two recovery modes:

- **Deep recovery (`dr`)** — scans a raw device or disk image byte-by-byte
  for known file signatures (magic headers/footers) and carves out matching
  files. Useful on formatted or repartitioned devices where filesystem
  metadata is gone but the file content may still be intact.
- **Quick recovery (`qr`)** — recovers specific deleted files by inode,
  using [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) (`fls`,
  `istat`, `icat`, `fsstat`). Useful when the filesystem metadata is still
  present (e.g. recently deleted files). If a direct inode lookup comes up
  empty (common on ext3/ext4, where deleting a file clears the inode's
  metadata immediately), `qr` automatically falls back to a signature scan
  scoped to the area the file's data is likely still sitting in, instead of
  giving up or requiring a full-device `dr` scan.

## Requirements

- Python 3
- For quick recovery (`qr`) only: [The Sleuth Kit](https://www.sleuthkit.org/)
  installed and on your `PATH` (provides `fls`, `istat`, `icat`, `fsstat`)
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
| `-f`, `--file_types` | Comma-separated file types for `dr` to scan for (e.g. `jpg,png,pdf`). Default: `jpg`. Not used by `qr` |
| `-o`, `--output_path` | Directory to write recovered files to. Created automatically if missing. Default: `recovered` |
| `-i`, `--inodes` | Inode(s) for quick recovery, e.g. `12341:photo.jpg,12342:report.pdf`. If omitted, `qr` lists deleted files interactively |
| `-v`, `--version` | Print the tool's version and exit |

### Supported file types

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

If the inode's data can't be read directly, `qr` falls back to a scoped
signature scan automatically and writes any match as `inode<N>_<n>.<ext>`
in the output directory — this is a best-effort heuristic, not a guarantee.

## When is a deleted file actually recoverable?

Deleting a file usually only removes the directory entry/inode pointer —
the underlying data blocks stay on disk until something else overwrites
them. Whether this tool (or any recovery tool) can get the file back
depends entirely on whether those bytes still exist on the medium.

### Likely recoverable

These only unlink the file or rewrite metadata, leaving the actual data
blocks untouched:

- `rm`, `rm -f`, `rm -rf`, deleting via a file manager, moving to Trash
- An application calling `unlink()` internally (e.g. `git rm`, most "delete"
  buttons in software)
- A quick format (`mkfs` without a wipe pass) — old data blocks are usually
  still present, which is exactly the scenario `dr` targets
- Deletion on a plain **HDD** with no TRIM involved — blocks sit untouched
  until actually overwritten by new writes
- `rm`/`rm -rf` on **ext3/ext4** — the inode's metadata is cleared
  immediately, so `qr`'s direct inode lookup comes back empty, but the data
  blocks themselves are untouched; `qr`'s scoped-carve fallback can usually
  still get the file back in this case

### Not recoverable

These actively overwrite or physically erase the data, so the original
bytes no longer exist anywhere to carve out:

- `shred`, and secure-delete tools like `srm`, `wipe`, `scrub`
- `dd if=/dev/zero` / `dd if=/dev/urandom` over a file, partition, or device
- `blkdiscard`, `fstrim`, or any filesystem mounted with `discard` — these
  send **TRIM** commands that make an SSD's firmware erase the underlying
  flash cells almost immediately, independent of any later overwrite
- An SSD's own internal garbage collection, which can reclaim unmapped
  blocks on its own — this is why recovery is generally much harder on SSDs
  than on HDDs
- `cryptsetup luksErase` or discarding an encryption header — the
  ciphertext may still be there, but without the key it's unreadable
- Ordinary disk activity after deletion (installing software, copying large
  files, logging) that happens to reuse the freed blocks

This is a physical limitation, not something software can work around: no
recovery tool can carve out bytes that have been overwritten or TRIMed off
the storage medium. The best mitigation is prevention — stop writing to the
affected device immediately after an accidental delete (unmount it if
possible) and recover from a **copy/image** rather than the live device.

## Notes

- Deep recovery relies on recognizing file signatures and, for some types,
  a trailing size limit instead of a true end marker — recovered files are
  not guaranteed to be complete or valid, especially for fragmented files.
- Run against a **copy/image** of the device whenever possible rather than
  the live device, to avoid further overwriting recoverable data.
