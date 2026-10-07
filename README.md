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
  (e.g. recently deleted files). If `icat` comes back with 0 bytes — which
  happens on ext3/ext4, where deleting a file zeroes the inode's block
  pointers immediately (see below) — `qr` automatically falls back to a
  signature scan scoped to just that inode's block group, instead of giving
  up or requiring a full-device `dr` scan.

## Requirements

- Python 3
- For quick recovery (`qr`) only: [The Sleuth Kit](https://www.sleuthkit.org/)
  installed and on your `PATH` (provides `fls`, `istat`, `icat`, and
  `fsstat`, the last one used by the scoped-carve fallback described below)
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

### Scoped-carve fallback (ext3/ext4 zeroed inodes)

On ext3/ext4, deleting a file truncates its inode — clearing the block
pointers — as soon as the link count hits zero, even though the actual file
content is usually still sitting untouched on disk (see the next section).
`icat` then "succeeds" but writes 0 bytes, since it has nothing left to read
the data from by inode alone.

When that happens, `qr` automatically:

1. Reads the inode's block group number via `istat`.
2. Reads that block group's byte range via `fsstat`. If the filesystem uses
   `flex_bg` (the `mke2fs` default for a long time now), the scan is
   widened to the inode's whole **flex group cluster** instead of just its
   single nominal block group — under flex_bg, a file's data blocks can
   land anywhere in that cluster, not only the group the inode itself is
   in, so a single-group scan can easily miss data that is still right
   there.
3. Runs the same signature-based carving `dr` uses, but **confined to that
   area** instead of scanning the whole device — so you still get the file
   back without also pulling in unrelated files from elsewhere on the disk
   the way a full `dr` scan would.

If nothing is found even in that widened area, `qr` says so explicitly
(`No <type> signature found in ...`) instead of quietly doing nothing, and
suggests running a full `dr` scan as the next step.

The file type to scan for is resolved the same way `dr` is told what to
look for, just automatically: it first re-reads `fls -r` to find the
inode's **real original filename** and uses its extension (e.g. inode 13
was really `original_photo.png`, so it scans for `png`) — not the name you
happen to save the (empty) `icat` output as, which might not match at all.
Only if the original name is gone or has no recognized extension does it
fall back to the extension of the output filename you gave, then to
whatever `-f` was given (default `jpg`). Results from this fallback are
written as `inode<N>_<n>.<ext>` so they never collide with a previous
`dr`/`qr` run's output in the same folder.

Note: once a deleted inode shows up under `fls -r`'s `$OrphanFiles` as
`OrphanFile-<N>` instead of its real name, the directory entry itself is
gone too (not just the inode's block pointers) — at that point even `fls`
no longer knows the original filename, so the extension you give on the
command line (or `-f`) is the only source left for picking a scan type.

```bash
sudo python pyforensics.py qr /dev/sda1 -i 13:photo.png -o ./out
# icat returned no data for inode 13 - its block pointers were likely
# cleared on delete (common on ext3/ext4).
# Falling back to a signature scan of block group 0 (0-134217728 bytes)...
# -> ./out/inode13_0.png
```

This is still a best-effort heuristic, not a guarantee: ext4's allocator
usually keeps a file's data blocks within its inode's flex group for
performance, but under heavy fragmentation or when that whole cluster is
nearly full it can place them elsewhere, in which case the scoped scan
won't find them and a full `dr` scan (or journal-based recovery with a
tool like `extundelete`) is the next step.

## When is a deleted file actually recoverable?

Deleting a file on Linux usually only removes the directory entry/inode
pointer — the underlying data blocks stay on disk until something else
overwrites them. Whether this tool (or any recovery tool) can get the file
back depends entirely on whether those bytes still exist on the medium.

### Likely recoverable

These only unlink the file or rewrite metadata, leaving the actual data
blocks untouched:

- `rm`, `rm -f`, `rm -rf`, deleting via a file manager, moving to Trash
- An application calling `unlink()` internally (e.g. `git rm`, most "delete"
  buttons in software)
- A quick format (`mkfs` without a wipe pass) — old data blocks are usually
  still present, which is exactly the scenario `dr` (deep/signature-based
  recovery) targets
- Deletion on a plain **HDD** with no TRIM involved — blocks sit untouched
  until actually overwritten by new writes
- `rm`/`rm -rf` on **ext3/ext4** specifically — the inode's block pointers
  get zeroed immediately, so `qr`'s plain `icat` step comes back empty, but
  the data blocks themselves are untouched. This is a metadata problem, not
  a physical one, which is why `qr`'s scoped-carve fallback (above) can
  usually still get the file back even though a direct inode lookup can't.

### Not recoverable

These actively overwrite or physically erase the data, so the original
bytes no longer exist anywhere to carve out:

- `shred`, and secure-delete tools like `srm`, `wipe`, `scrub`
- `dd if=/dev/zero` / `dd if=/dev/urandom` over a file, partition, or device
- `blkdiscard`, `fstrim` (including the `fstrim.timer` many distros run
  weekly by default), or any filesystem mounted with `discard` — these send
  **TRIM** commands that make an SSD's firmware erase the underlying flash
  cells almost immediately, independent of any later overwrite
- An SSD's own internal garbage collection, which can reclaim unmapped
  blocks on its own — this is why recovery is generally much harder on SSDs
  than on HDDs
- `cryptsetup luksErase` or discarding an encryption header — the
  ciphertext may still be there, but without the key it's unreadable
- Ordinary disk activity after deletion (installing software, copying large
  files, logging) that happens to reuse the freed blocks

### Can the code fix this?

No — this is a physical limitation, not a software bug. No recovery tool
can carve out bytes that have been overwritten or TRIMed off the storage
medium; the original data simply no longer exists to read. The best
mitigation is prevention: stop writing to the affected device immediately
after an accidental delete (unmount it if possible) and recover from a
**copy/image** rather than the live device, before TRIM or new writes can
run.

## Notes

- Deep recovery relies on recognizing file signatures and, for some types,
  a trailing size limit instead of a true end marker — recovered files are
  not guaranteed to be complete or valid, especially for fragmented files.
- Run against a **copy/image** of the device whenever possible rather than
  the live device, to avoid further overwriting recoverable data.
- `qr` executes external Sleuth Kit binaries (`fls`, `istat`, `icat`) found
  on your `PATH`.
