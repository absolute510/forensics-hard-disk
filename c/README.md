# cforensics (bản C)

Bản C của `pyforensics`: công cụ khôi phục file từ thiết bị/image đĩa thô. Một file nguồn duy nhất ([cforensics.c](cforensics.c)), C11, không cần thư viện ngoài.

- **Deep recovery (`dr`)**: quét signature (magic bytes đầu/cuối) trên cả thiết bị và cắt file ra. Dùng khi đã format hoặc mất metadata của filesystem.
- **Quick recovery (`qr`)**: khôi phục file đã xóa theo inode bằng [The Sleuth Kit](https://www.sleuthkit.org/) (`fls`, `istat`, `icat`, `fsstat`). Nếu `icat` ra 0 byte (thường gặp trên ext3/ext4), tự chuyển sang quét signature trong block/flex group của inode.

## Hệ điều hành

Windows, Linux, macOS. Đã build và test `dr` trên Windows 10 với GCC (MinGW). Nhánh Linux/macOS có trong code nhưng chưa chạy thử. `qr` chưa được test với Sleuth Kit thật.

## Build

```bash
cd c
make
```

hoặc:

```bash
gcc -O2 -Wall -Wextra -std=c11 -o cforensics cforensics.c
```

MSVC (Developer Command Prompt):

```
cl /utf-8 /O2 /W3 cforensics.c
```

## Cách dùng

```
cforensics <action> <device> [options]
```

| Tham số | Ý nghĩa |
|---|---|
| `dr` | Deep recovery |
| `qr` | Quick recovery (cần Sleuth Kit trong PATH) |
| `device` | Thiết bị hoặc image: `/dev/sda`, `disk.img`, `\\.\PhysicalDrive1` |

| Option | Ý nghĩa |
|---|---|
| `-f`, `--file_types LIST` | Loại file cho `dr`, cách nhau bằng dấu phẩy. Mặc định `jpg` |
| `-o`, `--output_path DIR` | Thư mục output. Mặc định `recovered` |
| `-i`, `--inodes LIST` | Inode cho `qr`, ví dụ `12341:a.jpg,12342:b.pdf`. Bỏ qua thì chạy tương tác |
| `-v`, `--version` | In phiên bản |
| `-h`, `--help` | Trợ giúp |

Loại file hỗ trợ: `jpg`, `png`, `pdf`, `exe`, `dll`, `rdl`, `bat`, `docx`, `xls`, `doc`, `psd`, `mp3`, `wav`, `mp4`.

## Ví dụ

```bash
# Quét image, lấy jpg và pdf
./cforensics dr disk.img -f jpg,pdf -o out

# Quét ổ thật trên Linux (cần root)
sudo ./cforensics dr /dev/sda -f jpg,png -o out

# Windows: mở terminal bằng Administrator
cforensics.exe dr \\.\PhysicalDrive1 -f jpg -o out

# Khôi phục theo inode
sudo ./cforensics qr /dev/sda1 -i 12341:photo.jpg -o out
```

File ra có tên `0.jpg`, `1.pdf`, ... theo thứ tự tìm thấy. Với `qr` dùng fallback quét signature thì tên là `inode<N>_<n>.<ext>`.

## Cách hoạt động của `dr`

Đọc thiết bị từng khối 1 MB vào một buffer duy nhất. Con trỏ `p` trỏ tới byte chưa xử lý đầu tiên và `len` là số byte còn lại, nên bỏ qua hay ghi n byte chỉ là `p += n; len -= n;`, không cắt hay copy chuỗi. Khi nạp thêm, chỉ vài byte đuôi (< 64) được `memmove` lên đầu buffer để signature nằm vắt qua ranh giới hai lần đọc vẫn liền nhau.

Hai pha, đổi qua lại:

1. **Tìm đầu file**: tìm signature `start` sớm nhất trong số các loại được chọn. Thấy thì mở file, ghi header, chuyển sang pha 2.
2. **Ghi file**: chỉ tìm marker `end` của loại đang ghi. Thấy marker (hoặc chạm kích thước tối đa) thì đóng file, quay về pha 1. Hết dữ liệu giữa chừng thì lưu phần đã có thành file partial.

Chi tiết nằm trong comment của [cforensics.c](cforensics.c).

## Độ chính xác của signature

| Loại | Trạng thái |
|---|---|
| `png` | Đầy đủ: 8 byte đầu, kết thúc bằng `IEND` + CRC |
| `pdf` | `%PDF-` (mọi phiên bản) đến `%%EOF` đầu tiên. PDF cập nhật tăng dần (nhiều `%%EOF`) có thể bị cắt sớm |
| `docx` | `PK\3\4` đến hết bản ghi EOCD (22 byte) |
| `jpg` | JFIF, Exif, raw. Ảnh Exif có thumbnail nhúng cũng chứa `ff d9` nên có thể bị cắt sớm |
| `exe`, `dll`, `rdl`, `bat`, `wav`, `mp3`, `mp4` | Giữ nguyên signature của bản Python, chỉ mang tính gợi ý. File ra có thể thừa, thiếu hoặc không hợp lệ |
| `doc`, `xls`, `psd` | Marker đầu và cuối giống nhau, nên file kéo dài tới lần xuất hiện header kế tiếp (hoặc kích thước tối đa) |

Hiểu đúng cấu trúc các định dạng còn lại (PE, RIFF, MP4 box, OLE2, PSD) cần parse thật, chưa làm.

## Lưu ý

- Chạy trên bản copy (image) của ổ, không chạy trên ổ đang dùng, để tránh ghi đè dữ liệu còn khôi phục được.
- Không công cụ nào khôi phục được dữ liệu đã bị ghi đè, shred hoặc TRIM. Xem phần "When is a deleted file actually recoverable?" trong [README gốc](../README.md).
- Với `qr`, đường dẫn thiết bị bị từ chối nếu chứa ký tự shell nguy hiểm (`"`, `` ` ``, `$`, `&`, `|`, ...), inode chỉ nhận chữ số và `-`, tên file output không được chứa `/` hoặc `\`.
