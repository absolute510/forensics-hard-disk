#!/usr/bin/python
import argparse
import subprocess
import os

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
            "start": b'\x50\x4e\x47',
            "end": b'\xff\xfc\xfd\xfe',
            }
        ],
        "max_size": 155000000
    },
    "pdf": {
        "patterns": [
            {
            "start": b'\x25\x50\x44\x46\x2d\x31',
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
            "start": b'\x57\x41\x56\45',
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

# Size of bytes to read
size = 512

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
    help=('File types for deep recovery to scan separated by comma. Ex: jpg,png,exe. [default=jpg]'),
)
parser.add_argument(
    '-o', '--output_path', type=str, nargs='?', dest='output_path', default='recovered',
    help=('Output recovered files to this directory [default=./recovered/]'),
)

def find_pattern(byte, file_types):
    start_found = -1
    end_found = -1
    for file_type in file_types:
        file_max_size = file_patterns[file_type]['max_size']
        for file_pattern in file_patterns[file_type]['patterns']:
            file_pattern_start = file_pattern['start']
            file_pattern_end = file_pattern['end']
            start_found = byte.find(file_pattern_start)
            end_found = byte.find(file_pattern_end)
            if start_found >= 0 or end_found >=0:
                return file_type, start_found, end_found, len(file_pattern_end), file_max_size
    return None, start_found, end_found, 0, 0


def deep_recover(device, output_path, file_types):
    # Open drive as raw bytes for read
    raw_device_read = open(device, "rb") 
    byte = raw_device_read.read(size)
    offset_location = 0
    recovery_mode = False
    recovered_file_id = 0
    recovered_file = None
    file_type = None
    written_byte = 0
    pattern_end_len = 0
    max_size = 0
    print("Scanning...")
    while byte:
        file_type_found, start_found, end_found, file_pattern_end_len, file_max_size = find_pattern(byte, file_types)
        if recovery_mode == False and start_found >=0:
            print('Found ' + str(file_type_found))
            recovery_mode = True
            file_type = file_type_found
            pattern_end_len = file_pattern_end_len
            max_size = file_max_size
            if not recovered_file:
                recovered_file = open(output_path + '/' + str(recovered_file_id) + '.' + file_type, 'wb')
            recovered_file.write(byte[start_found:])
            written_byte += len(byte[start_found:])
        
        if recovery_mode == True and start_found < 0:
            if end_found >= 0:
                recovered_file.write(byte[:end_found+pattern_end_len])
                print('Wrote file: ' + output_path + '/' + str(recovered_file_id) + '.' + file_type)
                recovery_mode = False
                written_byte = 0
                recovered_file_id += 1
                recovered_file.close()
                recovered_file = None
            elif written_byte + len(byte) >= max_size:
                recovered_file.write(byte[:file_max_size - written_byte])
                raw_device_read.seek((offset_location+1)*size)
                print('Wrote file: ' + output_path + '/' + str(recovered_file_id) + '.' + file_type)
                recovery_mode = False
                written_byte = 0
                recovered_file_id += 1
                recovered_file.close()
                recovered_file = None
            else:
                recovered_file.write(byte)
                written_byte += len(byte)
        byte = raw_device_read.read(size)
        offset_location += 1
    raw_device_read.close()

def print_red(text): print("\033[91m {}\033[00m" .format(text))

def quick_recover(device, outpath, inodes):
    if not inodes:
        print("Showing inode number of files:")
        fls_cmd = "fls -r " + device
        out = subprocess.check_output(fls_cmd, shell=True)
        for line in out.decode('utf-8').splitlines():
            print_red(line) if "*" in line else print(line)
        inode=input("Enter the inode of the deleted file:  ")
        os.system("istat "+ device + " " + inode )
        print("Enter the name of the file where data to be stored (with extension): ")
        newfile=input("")
        os.system("icat "+ device +" "+ inode +" > "+ outpath + '/' + newfile )
        print('Wrote file: ' + outpath + '/' + newfile)
    else:
        for file in inodes.split(','):
            inode = file.split(':')[0]
            file_name = file.split(':')[1]
            print('Recovering inode: ' + inode)
            os.system("icat "+ device +" "+ inode +" > "+ outpath + '/' + file_name )
            print('Wrote file: ' + outpath + '/' + file_name)


if __name__ == '__main__':
    args = parser.parse_args()
    action = args.action[0]
    device = args.device[0]
    outpath = args.output_path
    file_types = args.file_types.split(",") if args.file_types else ['jpg']

    # Create a new directory because it does not exist
    if outpath and not os.path.exists(outpath):
        os.makedirs(outpath)
    if action == "dr":
        deep_recover(device, outpath, file_types)
    if action == "qr":
        quick_recover(device, outpath, args.inodes)