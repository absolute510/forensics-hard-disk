#!/usr/bin/python
import argparse
import re
import subprocess
import os

VERSION = "1.0.0"

file_patterns = {
    "jpg": {
        "patterns": [
            {
            "start": b'\xff\xd8\xff\xe0\x00\x10\x4a\x46',
            "end": b'\xff\xd9',
            }
        ],
        "max_size": 155000000
    },
    "png": {
        "patterns": [
            {
            "start": b'\x89\x50\x4e\x47',
            "end": b'\xff\xfc\xfd\xfe',
            }
        ],
        "max_size": 155000000
    },
    "pdf": {
        "patterns": [
            {
            "start": b'\x25\x50\x44\x46\x2d\x31\x2e\x34',
            "end": b'\x25\x25\x45\x4f\x46\x0d',
            }
        ],
        "max_size": 155000000
    },
    "exe": {
        "patterns": [
            {
            "start": b'\x4d\x5a\x50',
            "end": b'\x4d\x5a',
            }
        ],
        "max_size": 155000000
    },
    "dll": {
        "patterns": [
            {
            "start": b'\x4d\x5a\x90',
            "end": b'\x4d\x5a',
            }
        ],
        "max_size": 155000000
    },
    "rdl": {
        "patterns": [
            {
            "start": b'\x3c\x3f\x78\x6d\x6c\x20',
            "end": b'\x3c\x2f\x52\x65\x70\x6f\x72\x74\x3e',
            }
        ],
        "max_size": 155000000
    },
    "bat": {
        "patterns": [
            {
            "start": b'\x40\x45\x43\x48\x4f\x20\x4f\x46',
            "end": b'\x45\x4e\x44\x0d\x0a',
            }
        ],
        "max_size": 155000000
    },
    "docx": {
        "patterns": [
            {
            "start": b'\x50\x4b\x03\x04\x14\x00',
            "end": b'\x50\x4B\x05\x06',
            }
        ],
        "max_size": 10485760
    },
    "xls": {
        "patterns": [
            {
            "start": b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3b\x00',
            "end": b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3b\x00',
            }
        ],
        "max_size": 10485760
    },

    "doc": {
        "patterns": [
            {
            "start": b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00',
            "end": b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00',
            }
        ],
        "max_size": 10485760
    },
    "psd": {
        "patterns": [
            {
            "start": b'\x38\x42\x50\x53\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03',
            "end": b'\x38\x42\x50\x53\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03',
            }
        ],
        "max_size": 155000000
    },
    "mp3": {
        "patterns": [
            {
            # FIX: was b'\x57\x41\x56\45' - the trailing "\45" is a 1-3 digit
            # OCTAL escape in a Python bytes literal (= 0x25 '%'), not hex 0x45
            # 'E'. That silently produced the wrong 4th byte and this pattern
            # could never match real data. Now reads \x45 so the literal bytes
            # are what the signature was meant to contain.
            "start": b'\x57\x41\x56\x45',
            "end": b'\x00\x00\xff',
            },
            {
            "start": b'\xff\xfb\xd0',
            "end": b'\xd1\x35\x51\xcc',
            }
        ],
        "max_size": 155000000
    },
    "wav": {
        "patterns": [
            {
            "start": b'\x52\x49\x46\x46',
            "end": b'\x4c\x65\x6f\x64',
            }
        ],
        "max_size": 155000000
    },
    "mp4": {
        "patterns": [
            {
            "start": b'\x00\x00\x00\x20\x66\x74\x79\x70\x6d\x70\x34\x32',
            "end": b'\x5a\x5d\xe0\x82\x14\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xbc',
            }
        ],
        "max_size": 155000000
    },
}

# FIX: old code read fixed, non-overlapping 512-byte blocks and matched
# patterns independently within each block. Any signature longer than what
# was left in a block (easy with the 26-byte doc/xls header) could get split
# across two reads and never match at all. deep_recover() below now reads
# in bigger chunks into a persistent, overlapping buffer so a pattern
# straddling a read boundary is still seen whole.
READ_SIZE = 1024 * 1024

parser = argparse.ArgumentParser(
    description='Python File Recovery Private Edition',
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    'action', type=str, nargs=1,
    help='Action to take:\ndr: deep recovery for formated, partitioned devices\nqr: quick recovery for deleted file'
)
parser.add_argument(
    'device', type=str, nargs=1,
    help='Path to device. Ex: /dev/sda',
)
parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help='Show version')
parser.add_argument(
        "-i",
        "--inodes",
        help='Inodes for quick recovery. Ex: 12341:file1.doc,12342:file2.pdf')
parser.add_argument(
    '-f', '--file_types', type=str, nargs='?', dest='file_types', default='jpg',
    help=('File types to scan for, separated by comma. Ex: jpg,png,exe. [default=jpg]\n'
          'Used by deep recovery (dr), and as a fallback hint for quick\n'
          'recovery (qr) when icat returns no data and the output filename\n'
          'has no recognized extension.'),
)
parser.add_argument(
    '-o', '--output_path', type=str, nargs='?', dest='output_path', default='recovered',
    help=('Output recovered files to this directory [default=./recovered/]'),
)


def find_start(buf, file_types):
    """Search for the earliest 'start' pattern of any requested file_type in buf."""
    best_idx = -1
    best_type = None
    best_pattern = None
    for file_type in file_types:
        for pattern in file_patterns[file_type]['patterns']:
            idx = buf.find(pattern['start'])
            if idx >= 0 and (best_idx == -1 or idx < best_idx):
                best_idx = idx
                best_type = file_type
                best_pattern = pattern
    return best_type, best_idx, best_pattern


def max_pattern_len(file_types, key):
    return max(
        (len(pattern[key]) for file_type in file_types for pattern in file_patterns[file_type]['patterns']),
        default=0,
    )


def deep_recover(device, output_path, file_types, start_offset=0, end_offset=None, name_prefix=''):
    # FIX: original find_pattern() re-scanned ALL requested file_types for a
    # START pattern on every single iteration, even while a file was already
    # being recovered. A JPEG's own embedded EXIF thumbnail re-triggers the
    # JPEG start marker, so the old "recovery_mode == True and start_found >= 0"
    # case fell through both ifs and silently dropped that 512-byte block from
    # the output (data loss). Below, once recovering=True we only ever search
    # for the current file's END pattern - start patterns are never looked at
    # again until the current file is closed, so there is no such gap.
    #
    # start_offset/end_offset let a caller confine the scan to a byte range
    # instead of the whole device - used by quick_recover()'s scoped-carve
    # fallback so it only scans the inode's own block group rather than the
    # entire disk. name_prefix keeps those scoped recoveries from colliding
    # with/overwriting file names from a previous dr/qr run in the same
    # output directory.
    raw_device_read = open(device, "rb")
    if start_offset:
        raw_device_read.seek(start_offset)
    position = start_offset

    def read_chunk():
        nonlocal position
        to_read = READ_SIZE
        if end_offset is not None:
            remaining = end_offset - position
            if remaining <= 0:
                return b""
            to_read = min(to_read, remaining)
        data = raw_device_read.read(to_read)
        position += len(data)
        return data

    start_reserve = max(max_pattern_len(file_types, 'start') - 1, 0)

    buffer = b""
    recovering = False
    current_type = None
    current_pattern = None
    max_size = 0
    written = 0
    recovered_file_id = 0
    recovered_file = None

    print("Scanning...")
    try:
        while True:
            chunk = read_chunk()
            buffer += chunk

            progressed = True
            while progressed:
                progressed = False

                if not recovering:
                    file_type, idx, pattern = find_start(buffer, file_types)
                    if idx >= 0:
                        print('Found ' + str(file_type))
                        recovering = True
                        current_type = file_type
                        current_pattern = pattern
                        max_size = file_patterns[file_type]['max_size']
                        recovered_file = open(
                            os.path.join(output_path, name_prefix + str(recovered_file_id) + '.' + file_type), 'wb'
                        )
                        # FIX: doc/xls/psd define identical start and end
                        # byte patterns in file_patterns above. We write the
                        # header out and advance buffer PAST it before ever
                        # searching for the end pattern, so that search can't
                        # immediately re-match the very bytes we just
                        # consumed as the start (old code would do exactly
                        # that and truncate these files to just the header).
                        header = buffer[idx:idx + len(pattern['start'])]
                        recovered_file.write(header)
                        written = len(header)
                        buffer = buffer[idx + len(pattern['start']):]
                        progressed = True
                    elif not chunk and len(buffer) <= start_reserve:
                        buffer = b""
                    elif len(buffer) > start_reserve:
                        # Nothing matched; keep only enough tail bytes to catch a
                        # start pattern that straddles this chunk boundary.
                        buffer = buffer[len(buffer) - start_reserve:] if start_reserve else b""
                else:
                    end_pattern = current_pattern['end']
                    end_idx = buffer.find(end_pattern)
                    if end_idx >= 0:
                        cut = end_idx + len(end_pattern)
                        recovered_file.write(buffer[:cut])
                        written += cut
                        print('Wrote file: ' + os.path.join(
                            output_path, name_prefix + str(recovered_file_id) + '.' + current_type))
                        recovered_file.close()
                        recovered_file = None
                        recovering = False
                        recovered_file_id += 1
                        buffer = buffer[cut:]
                        progressed = True
                    else:
                        reserve = max(len(end_pattern) - 1, 0)
                        safe_len = max(len(buffer) - reserve, 0)
                        if written + safe_len >= max_size:
                            # FIX: old code sliced with
                            # `byte[:file_max_size - written_byte]`, using
                            # file_max_size from the CURRENT find_pattern()
                            # call (almost always 0 when no pattern matched
                            # in this block) instead of the cached max_size
                            # for the file actually being recovered. That
                            # produced a negative slice and wrote garbage.
                            # `max_size` here is the value captured when this
                            # file started recovering, so `take` is correct.
                            take = max_size - written
                            recovered_file.write(buffer[:take])
                            written += take
                            print('Wrote file: ' + os.path.join(
                                output_path, name_prefix + str(recovered_file_id) + '.' + current_type))
                            recovered_file.close()
                            recovered_file = None
                            recovering = False
                            recovered_file_id += 1
                            buffer = buffer[take:]
                            progressed = True
                        elif safe_len > 0:
                            recovered_file.write(buffer[:safe_len])
                            written += safe_len
                            buffer = buffer[safe_len:]

            if not chunk:
                break

        if recovering and recovered_file:
            # FIX: old code's while-loop just exited at EOF (`while byte:`
            # becomes false) without ever closing the in-progress
            # recovered_file, so its last buffered writes could stay
            # unflushed and the final recovered file be incomplete. Flush
            # and close it here as a partial/truncated recovery instead of
            # silently dropping it.
            recovered_file.write(buffer)
            recovered_file.close()
            print('Wrote file (partial, no end marker found): ' + os.path.join(
                output_path, name_prefix + str(recovered_file_id) + '.' + current_type))
    finally:
        raw_device_read.close()


def print_red(text): print("\033[91m {}\033[00m" .format(text))


def get_inode_block_group(device, inode):
    """Return the block group number istat reports for `inode`, or None."""
    try:
        out = subprocess.run(["istat", device, inode], capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    match = re.search(r'^Group:\s*(\d+)', out, re.MULTILINE)
    return int(match.group(1)) if match else None


def get_group_byte_range(device, group):
    """Return (start_byte, end_byte) covered by block `group`, via fsstat, or None."""
    try:
        out = subprocess.run(["fsstat", device], capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    size_match = re.search(r'Block Size:\s*(\d+)', out)
    if not size_match:
        return None
    block_size = int(size_match.group(1))

    group_match = re.search(
        r'^Group:\s*' + str(group) + r':(.*?)(?=^Group:\s*\d+:|\Z)', out, re.MULTILINE | re.DOTALL
    )
    if not group_match:
        return None
    range_match = re.search(r'Block Range:\s*(\d+)\s*-\s*(\d+)', group_match.group(1))
    if not range_match:
        return None
    start_block, end_block = int(range_match.group(1)), int(range_match.group(2))
    return block_size * start_block, block_size * (end_block + 1)


def scoped_carve_by_inode(device, inode, file_types, outpath):
    """
    Fallback for quick_recover(): when icat has nothing to read because the
    filesystem already zeroed the inode's block pointers (see the ext3/ext4
    note below), locate the block group the inode belongs to and run the
    same signature-based carving deep_recover() does for a full device, but
    confined to that one group's byte range. This finds the file's actual
    content (still physically on disk, just no longer referenced by the
    inode) without scanning - and pulling in unrelated files from - the rest
    of the device the way a plain `dr` over the whole disk would.
    """
    group = get_inode_block_group(device, inode)
    if group is None:
        print('Could not determine the block group for inode ' + inode + ' (istat unavailable or inode gone).')
        return False

    byte_range = get_group_byte_range(device, group)
    if byte_range is None:
        print('Could not determine the byte range of block group ' + str(group) + ' (fsstat unavailable).')
        return False

    start_offset, end_offset = byte_range
    print('icat returned no data for inode ' + inode +
          ' - its block pointers were likely cleared on delete (common on ext3/ext4).')
    print('Falling back to a signature scan of block group ' + str(group) +
          ' (' + str(start_offset) + '-' + str(end_offset) + ' bytes) instead of the whole device...')
    deep_recover(device, outpath, file_types, start_offset=start_offset, end_offset=end_offset,
                 name_prefix='inode' + inode + '_')
    return True


def quick_recover(device, outpath, inodes, file_types):
    # FIX: original used os.system()/subprocess.check_output(..., shell=True)
    # with device/inode/filename string-concatenated into a shell command
    # line. Filenames here come from `fls` output on the target device, i.e.
    # from data an attacker could control - a filename containing shell
    # metacharacters (`; rm -rf ~`, backticks, `$(...)`) would execute as a
    # command. Passing argv lists to subprocess.run (shell=False, the
    # default) avoids the shell entirely, so those bytes are just a filename
    # again. Output redirection (`> outfile`) is replaced by writing to the
    # file handle directly via stdout=f.
    # FIX: on ext3/ext4, deleting a file truncates the inode (block pointers
    # are zeroed) as soon as its link count hits zero, so `icat <inode>` can
    # legitimately succeed (exit code 0) while writing 0 bytes, even though
    # the file's actual content is still physically on disk. When that
    # happens, fall back to scoped_carve_by_inode() instead of silently
    # leaving the caller with an empty file.
    if not inodes:
        print("Showing inode number of files:")
        out = subprocess.check_output(["fls", "-r", device])
        for line in out.decode('utf-8').splitlines():
            print_red(line) if "*" in line else print(line)
        inode = input("Enter the inode of the deleted file:  ")
        subprocess.run(["istat", device, inode])
        print("Enter the name of the file where data to be stored (with extension): ")
        newfile = input("")
        outfile = os.path.join(outpath, newfile)
        with open(outfile, 'wb') as f:
            subprocess.run(["icat", device, inode], stdout=f, check=True)
        print('Wrote file: ' + outfile)
        if os.path.getsize(outfile) == 0:
            ext = os.path.splitext(newfile)[1].lstrip('.').lower()
            candidate_types = [ext] if ext in file_patterns else file_types
            scoped_carve_by_inode(device, inode, candidate_types, outpath)
    else:
        for file in inodes.split(','):
            inode, file_name = file.split(':', 1)
            print('Recovering inode: ' + inode)
            outfile = os.path.join(outpath, file_name)
            with open(outfile, 'wb') as f:
                subprocess.run(["icat", device, inode], stdout=f, check=True)
            print('Wrote file: ' + outfile)
            if os.path.getsize(outfile) == 0:
                ext = os.path.splitext(file_name)[1].lstrip('.').lower()
                candidate_types = [ext] if ext in file_patterns else file_types
                scoped_carve_by_inode(device, inode, candidate_types, outpath)


if __name__ == '__main__':
    args = parser.parse_args()

    # FIX: -v/--version was declared but args.version was never read anywhere,
    # so the flag did nothing. It now actually prints a version and exits.
    if args.version:
        print('pyforensics ' + VERSION)
        raise SystemExit(0)

    action = args.action[0]
    device = args.device[0]
    outpath = args.output_path
    file_types = args.file_types.split(",") if args.file_types else ['jpg']

    # FIX: an unrecognized -f value (e.g. a typo like "jpeg") used to crash
    # deep_recover() with an uncaught KeyError the first time it indexed
    # file_patterns[file_type]. Validate up front and fail with a clear
    # message instead.
    unknown_types = [t for t in file_types if t not in file_patterns]
    if unknown_types:
        raise SystemExit(
            'Unknown file type(s): ' + ', '.join(unknown_types) +
            '\nValid types: ' + ', '.join(sorted(file_patterns.keys()))
        )

    # Create a new directory because it does not exist
    if outpath and not os.path.exists(outpath):
        os.makedirs(outpath)
    if action == "dr":
        deep_recover(device, outpath, file_types)
    if action == "qr":
        quick_recover(device, outpath, args.inodes, file_types)
