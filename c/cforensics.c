/*
 * cforensics - bản C của pyforensics (khôi phục file bằng signature + Sleuth Kit)
 *
 * Build:  gcc -O2 -Wall -Wextra -std=c11 -o cforensics cforensics.c      (hoặc: make)
 *         cl /utf-8 /O2 /W3 cforensics.c                                 (MSVC)
 *
 * BỐ CỤC FILE
 *   1. Bảng signature (FILE_TYPES)      - "đầu/đuôi" của từng loại file
 *   2. Hàm tiện ích                     - tìm chuỗi byte, in màu, tạo thư mục
 *   3. deep_recover()  (lệnh dr)        - quét thiết bị, cắt file theo signature
 *   4. Quick recovery  (lệnh qr)        - gọi Sleuth Kit, thất bại thì carve có phạm vi
 *   5. main()                           - đọc tham số dòng lệnh, chọn dr hoặc qr
 *
 * Ý TƯỞNG CỐT LÕI CỦA dr (dùng con trỏ):
 * Đọc thiết bị từng khối 1 MB vào MỘT buffer duy nhất. Con trỏ "p" trỏ tới byte
 * đầu tiên chưa xử lý, "len" là số byte còn lại kể từ p:
 *
 *     buf: [ đã xử lý ][p -> byte chưa xử lý ... (len byte) ]
 *
 * Xử lý xong n byte chỉ cần p += n; len -= n; (không cắt/copy chuỗi như
 * buffer = buffer[n:] trong Python). Lần duy nhất có copy là khi nạp thêm dữ liệu:
 * memmove vài byte đuôi (< MAX_RESERVE) lên đầu buffer, để signature nằm vắt qua
 * ranh giới hai lần đọc vẫn liền nhau trong bộ nhớ.
 */
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#define popen _popen
#define pclose _pclose
#define fseek64 _fseeki64
#define MKDIR(d) _mkdir(d)
#define PATH_SEP '\\'
#else
#include <sys/stat.h>
#include <sys/types.h>
#define fseek64 fseeko
#define MKDIR(d) mkdir((d), 0755)
#define PATH_SEP '/'
#endif

#define VERSION "1.0.0"
#define READ_SIZE (1024u * 1024u) /* mỗi lần đọc thiết bị 1 MB */
#define MAX_RESERVE 64u           /* chỗ chừa cho byte đuôi mang sang lần đọc sau; phải > độ dài signature dài nhất - 1 */
#define PATH_MAX_LEN 4096

/* Một chuỗi byte (signature) kèm độ dài; cần độ dài riêng vì signature có thể chứa byte 0x00 */
typedef struct {
    const unsigned char *data;
    size_t len;
} Bytes;

/* Một cặp nhận dạng: bytes mở đầu file và bytes kết thúc file */
typedef struct {
    Bytes start;
    Bytes end;
    size_t end_extra; /* số byte cố định nằm SAU marker end vẫn thuộc về file (vd. phần còn lại của ZIP EOCD) */
} Pattern;

/* Một loại file: tên/đuôi, danh sách pattern (mp3 có 2), và kích thước tối đa được ghi */
typedef struct {
    const char *name;
    const Pattern *patterns;
    size_t npatterns;
    uint64_t max_size;
} FileType;

/* B("...") đóng gói chuỗi literal thành Bytes; sizeof - 1 bỏ ký tự NUL kết thúc nên vẫn đúng với byte 0x00 */
#define B(s) { (const unsigned char *)(s), sizeof(s) - 1 }

#define MAX_BIG 155000000ULL
#define MAX_OFFICE 10485760ULL

/* JPEG: JFIF (e0), Exif (e1) và raw (db); marker kết thúc EOI ff d9.
 * Hạn chế: ảnh Exif có thumbnail nhúng cũng chứa ff d9 nên có thể bị cắt sớm. */
static const Pattern P_JPG[] = {
    {B("\xff\xd8\xff\xe0\x00\x10\x4a\x46"), B("\xff\xd9"), 0},
    {B("\xff\xd8\xff\xe1"), B("\xff\xd9"), 0},
    {B("\xff\xd8\xff\xdb"), B("\xff\xd9"), 0},
};
/* PNG: đủ 8 byte signature; kết thúc bằng chunk IEND + CRC cố định (ae 42 60 82) */
static const Pattern P_PNG[] = {{B("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"), B("\x49\x45\x4e\x44\xae\x42\x60\x82"), 0}};
/* PDF: "%PDF-" (mọi phiên bản, không chỉ 1.4), kết thúc "%%EOF" (không bắt buộc kèm \r) */
static const Pattern P_PDF[] = {{B("\x25\x50\x44\x46\x2d"), B("\x25\x25\x45\x4f\x46"), 0}};
static const Pattern P_EXE[] = {{B("\x4d\x5a\x50"), B("\x4d\x5a"), 0}};
static const Pattern P_DLL[] = {{B("\x4d\x5a\x90"), B("\x4d\x5a"), 0}};
static const Pattern P_RDL[] = {{B("\x3c\x3f\x78\x6d\x6c\x20"), B("\x3c\x2f\x52\x65\x70\x6f\x72\x74\x3e"), 0}};
static const Pattern P_BAT[] = {{B("\x40\x45\x43\x48\x4f\x20\x4f\x46"), B("\x45\x4e\x44\x0d\x0a"), 0}};
/* DOCX (ZIP): kết thúc bằng End Of Central Directory "PK\5\6" + 18 byte cố định còn lại (tổng 22 byte) */
static const Pattern P_DOCX[] = {{B("\x50\x4b\x03\x04\x14\x00"), B("\x50\x4b\x05\x06"), 18}};
#define XLS_SIG "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3b\x00"
#define DOC_SIG "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00"
#define PSD_SIG "\x38\x42\x50\x53\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03"
static const Pattern P_XLS[] = {{B(XLS_SIG), B(XLS_SIG), 0}};
static const Pattern P_DOC[] = {{B(DOC_SIG), B(DOC_SIG), 0}};
static const Pattern P_PSD[] = {{B(PSD_SIG), B(PSD_SIG), 0}};
static const Pattern P_MP3[] = {
    {B("\x57\x41\x56\x45"), B("\x00\x00\xff"), 0},
    {B("\xff\xfb\xd0"), B("\xd1\x35\x51\xcc"), 0},
};
static const Pattern P_WAV[] = {{B("\x52\x49\x46\x46"), B("\x4c\x65\x6f\x64"), 0}};
static const Pattern P_MP4[] = {{
    B("\x00\x00\x00\x20\x66\x74\x79\x70\x6d\x70\x34\x32"),
    B("\x5a\x5d\xe0\x82\x14\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xb4\xbc"),
    0,
}};

#define FT(n, p, m) { n, p, sizeof(p) / sizeof((p)[0]), m }
static const FileType FILE_TYPES[] = {
    FT("jpg", P_JPG, MAX_BIG),    FT("png", P_PNG, MAX_BIG),   FT("pdf", P_PDF, MAX_BIG),
    FT("exe", P_EXE, MAX_BIG),    FT("dll", P_DLL, MAX_BIG),   FT("rdl", P_RDL, MAX_BIG),
    FT("bat", P_BAT, MAX_BIG),    FT("docx", P_DOCX, MAX_OFFICE), FT("xls", P_XLS, MAX_OFFICE),
    FT("doc", P_DOC, MAX_OFFICE), FT("psd", P_PSD, MAX_BIG),   FT("mp3", P_MP3, MAX_BIG),
    FT("wav", P_WAV, MAX_BIG),    FT("mp4", P_MP4, MAX_BIG),
};
#define N_TYPES (sizeof(FILE_TYPES) / sizeof(FILE_TYPES[0]))

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

/* Tìm needle trong hay (như memmem, vốn không có sẵn trên Windows).
 * Trả về con trỏ tới chỗ khớp đầu tiên, hoặc NULL. Dùng memchr nhảy tới byte đầu
 * của needle cho nhanh, rồi memcmp để xác nhận. */
static const unsigned char *find_bytes(const unsigned char *hay, size_t hlen,
                                       const unsigned char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen) return NULL;
    const unsigned char *last = hay + (hlen - nlen);
    const unsigned char *cur = hay;
    while (cur <= last) {
        cur = memchr(cur, needle[0], (size_t)(last - cur) + 1);
        if (!cur) return NULL;
        if (memcmp(cur, needle, nlen) == 0) return cur;
        cur++;
    }
    return NULL;
}

static int type_index(const char *name)
{
    for (size_t i = 0; i < N_TYPES; i++)
        if (strcmp(FILE_TYPES[i].name, name) == 0) return (int)i;
    return -1;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }

static void print_valid_types(FILE *out)
{
    const char *names[N_TYPES];
    for (size_t i = 0; i < N_TYPES; i++) names[i] = FILE_TYPES[i].name;
    qsort(names, N_TYPES, sizeof(names[0]), cmp_str);
    for (size_t i = 0; i < N_TYPES; i++) fprintf(out, "%s%s", i ? ", " : "", names[i]);
    fputc('\n', out);
}

static void print_red(const char *text) { printf("\033[91m %s\033[00m\n", text); }

static void make_dir(const char *path)
{
    if (MKDIR(path) != 0 && errno != EEXIST) {
        fprintf(stderr, "Cannot create directory '%s': %s\n", path, strerror(errno));
        exit(1);
    }
}

/* ------------------------------------------------------------------ */
/* deep recovery                                                       */
/* ------------------------------------------------------------------ */

/* "Cửa sổ" trượt trên thiết bị: trạng thái đọc của deep_recover */
typedef struct {
    FILE *f;            /* thiết bị/image đang đọc */
    uint64_t pos;       /* vị trí byte tiếp theo sẽ đọc trên thiết bị */
    uint64_t end;       /* điểm dừng; chỉ có nghĩa khi has_end (dùng cho quét theo vùng ở qr) */
    int has_end;
    unsigned char *buf; /* vùng nhớ cấp phát một lần, kích thước READ_SIZE + MAX_RESERVE */
    unsigned char *p;   /* con trỏ tới byte đầu tiên chưa xử lý */
    size_t len;         /* số byte chưa xử lý tính từ p */
} Window;

/* Nạp thêm dữ liệu: dời vài byte đuôi còn sót lên đầu buffer (memmove), rồi đọc nối
 * thêm một khối ngay sau chúng. Trả về số byte đọc được; 0 nghĩa là hết dữ liệu/hết vùng. */
static size_t window_fill(Window *w)
{
    size_t want = READ_SIZE;
    if (w->has_end) {
        if (w->pos >= w->end) return 0;
        uint64_t remaining = w->end - w->pos;
        if (remaining < want) want = (size_t)remaining;
    }
    memmove(w->buf, w->p, w->len);
    w->p = w->buf;
    size_t n = fread(w->buf + w->len, 1, want, w->f);
    w->len += n;
    w->pos += n;
    return n;
}

static void out_name(char *dst, size_t cap, const char *dir, const char *prefix, unsigned long id, const char *ext)
{
    snprintf(dst, cap, "%s%c%s%lu.%s", dir, PATH_SEP, prefix, id, ext);
}

static FILE *open_out(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Cannot create '%s': %s\n", path, strerror(errno));
        exit(1);
    }
    return f;
}

/*
 * Quét [start_offset, end_offset) của thiết bị (cả thiết bị nếu has_end = 0) và cắt
 * các file khớp signature của các loại trong types[]. Tên file ra: <prefix><số>.<đuôi>.
 * Trả về số file đã ghi, hoặc -1 nếu không mở được thiết bị.
 *
 * Máy trạng thái hai pha, điều khiển bởi biến "recovering":
 *   recovering = 0 : đang TÌM ĐẦU FILE   (tìm "start" của mọi loại được chọn)
 *   recovering = 1 : đang GHI FILE       (chỉ tìm "end" của loại đang ghi)
 */
static long deep_recover(const char *device, const char *outdir, const int *types, size_t ntypes,
                         uint64_t start_offset, int has_end, uint64_t end_offset, const char *prefix)
{
    Window w = {0};
    w.f = fopen(device, "rb");
    if (!w.f) {
        fprintf(stderr, "Cannot open '%s': %s\n", device, strerror(errno));
        return -1;
    }
    if (start_offset && fseek64(w.f, (long long)start_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Cannot seek to offset %" PRIu64 " in '%s'\n", start_offset, device);
        fclose(w.f);
        return -1;
    }
    w.pos = start_offset;
    w.has_end = has_end;
    w.end = end_offset;
    w.buf = malloc(READ_SIZE + MAX_RESERVE);
    if (!w.buf) {
        fprintf(stderr, "Out of memory\n");
        fclose(w.f);
        return -1;
    }
    w.p = w.buf;

    /* start_reserve = độ dài signature "start" dài nhất - 1. Khi không thấy gì, chỉ cần giữ
     * lại chừng đó byte đuôi: một signature chỉ có thể bắt đầu dở dang trong đoạn này. */
    size_t start_reserve = 0;
    for (size_t t = 0; t < ntypes; t++) {
        const FileType *ft = &FILE_TYPES[types[t]];
        for (size_t k = 0; k < ft->npatterns; k++)
            if (ft->patterns[k].start.len - 1 > start_reserve) start_reserve = ft->patterns[k].start.len - 1;
    }

    int recovering = 0;
    const FileType *cur_type = NULL;
    const Pattern *cur_pat = NULL;
    uint64_t written = 0;
    unsigned long file_id = 0;
    FILE *out = NULL;
    char path[PATH_MAX_LEN];

    puts("Scanning...");
    for (;;) {
        /* Vòng ngoài: mỗi lượt nạp thêm 1 khối, rồi xử lý cho tới khi buffer "cạn" */
        size_t got = window_fill(&w);
        int progressed = 1;
        while (progressed) { /* vòng trong: lặp lại chừng nào còn xử lý được thêm trên buffer hiện tại */
            progressed = 0;
            if (!recovering) {
                /* --- PHA 1: tìm đầu file --- */
                /* Lấy signature "start" xuất hiện SỚM NHẤT trong buffer trong số mọi loại được chọn
                 * (hòa vị trí thì loại đứng trước trong danh sách thắng). Khi đã có ứng viên "best",
                 * chỉ cần tìm trong đoạn tới best + (độ dài signature) vì xa hơn thì không thể sớm hơn. */
                const unsigned char *best = NULL;
                const FileType *best_type = NULL;
                const Pattern *best_pat = NULL;
                for (size_t t = 0; t < ntypes; t++) {
                    const FileType *ft = &FILE_TYPES[types[t]];
                    for (size_t k = 0; k < ft->npatterns; k++) {
                        const Pattern *pat = &ft->patterns[k];
                        size_t limit = best ? (size_t)(best - w.p) + pat->start.len - 1 : w.len;
                        if (limit > w.len) limit = w.len;
                        const unsigned char *hit = find_bytes(w.p, limit, pat->start.data, pat->start.len);
                        if (hit && (!best || hit < best)) {
                            best = hit;
                            best_type = ft;
                            best_pat = pat;
                        }
                    }
                }
                if (best) {
                    printf("Found %s\n", best_type->name);
                    recovering = 1;
                    cur_type = best_type;
                    cur_pat = best_pat;
                    out_name(path, sizeof path, outdir, prefix, file_id, cur_type->name);
                    out = open_out(path);
                    /* Write the header and move p PAST it before searching for the end marker,
                     * so types whose start == end (doc/xls/psd) don't re-match themselves. */
                    fwrite(best, 1, best_pat->start.len, out);
                    written = best_pat->start.len;
                    size_t consumed = (size_t)(best - w.p) + best_pat->start.len;
                    w.p += consumed;
                    w.len -= consumed;
                    progressed = 1;
                } else if (!got && w.len <= start_reserve) {
                    w.len = 0; /* hết dữ liệu và phần đuôi quá ngắn để chứa signature: bỏ */
                } else if (w.len > start_reserve) {
                    /* Không thấy đầu file nào: bỏ phần đã quét (chỉ dời con trỏ p, không copy)
                     * và giữ lại đoạn đuôi có thể là phần đầu của signature bị cắt đôi. */
                    w.p += w.len - start_reserve;
                    w.len = start_reserve;
                }
            } else {
                /* --- PHA 2: đang ghi file; chỉ tìm marker "end" của loại hiện tại --- */
                const Bytes *endp = &cur_pat->end;
                const unsigned char *hit = find_bytes(w.p, w.len, endp->data, endp->len);
                if (hit) {
                    /* Thấy marker kết thúc: ghi mọi thứ từ p tới hết marker (+ end_extra byte theo sau) rồi đóng file */
                    size_t before = (size_t)(hit - w.p);
                    size_t cut = before + endp->len + cur_pat->end_extra;
                    if (cut > w.len && got) {
                        /* Phần end_extra chưa nạp đủ: ghi tới sát marker, dời p tới marker rồi chờ lần nạp sau
                         * (chỉ còn < MAX_RESERVE byte trong buffer nên memmove vẫn an toàn) */
                        fwrite(w.p, 1, before, out);
                        written += before;
                        w.p += before;
                        w.len -= before;
                    } else {
                        if (cut > w.len) cut = w.len; /* hết dữ liệu: lấy hết những gì còn */
                        fwrite(w.p, 1, cut, out);
                        written += cut;
                        out_name(path, sizeof path, outdir, prefix, file_id, cur_type->name);
                        printf("Wrote file: %s\n", path);
                        fclose(out);
                        out = NULL;
                        recovering = 0;
                        file_id++;
                        w.p += cut;
                        w.len -= cut;
                        progressed = 1;
                    }
                } else {
                    /* Chưa thấy marker. Phần "an toàn" để ghi ngay = tất cả trừ (độ dài end - 1) byte cuối,
                     * vì marker có thể đang nằm dở ở đuôi buffer và hoàn tất ở lần đọc sau. */
                    size_t reserve = endp->len - 1;
                    size_t safe_len = w.len > reserve ? w.len - reserve : 0;
                    if (written + safe_len >= cur_type->max_size) {
                        /* Chạm giới hạn kích thước: cắt đúng max_size và đóng file (không có marker) */
                        size_t take = (size_t)(cur_type->max_size - written);
                        fwrite(w.p, 1, take, out);
                        written += take;
                        out_name(path, sizeof path, outdir, prefix, file_id, cur_type->name);
                        printf("Wrote file: %s\n", path);
                        fclose(out);
                        out = NULL;
                        recovering = 0;
                        file_id++;
                        w.p += take;
                        w.len -= take;
                        progressed = 1;
                    } else if (safe_len > 0) {
                        /* Ghi phần an toàn, giữ đuôi lại cho lần nạp sau */
                        fwrite(w.p, 1, safe_len, out);
                        written += safe_len;
                        w.p += safe_len;
                        w.len -= safe_len;
                    }
                }
            }
        }
        if (!got) break; /* hết thiết bị/vùng quét */
    }

    /* Hết dữ liệu giữa lúc đang ghi một file: lưu phần đã có thành file "partial" thay vì bỏ mất */
    if (recovering && out) {
        fwrite(w.p, 1, w.len, out);
        fclose(out);
        out_name(path, sizeof path, outdir, prefix, file_id, cur_type->name);
        printf("Wrote file (partial, no end marker found): %s\n", path);
        file_id++;
    }
    free(w.buf);
    fclose(w.f);
    return (long)file_id;
}

/* ------------------------------------------------------------------ */
/* quick recovery via The Sleuth Kit                                   */
/* ------------------------------------------------------------------ */

/* Lệnh Sleuth Kit chạy qua shell (popen) nên phải từ chối ký tự shell có thể diễn giải
 * (chống command injection qua đường dẫn thiết bị). Inode và tên file có hàm kiểm tra riêng bên dưới. */
static int safe_arg(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++)
        if (strchr("\"`$%!^&|<>;\n\r", *s)) return 0;
    return 1;
}

static int valid_inode(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s) && *s != '-') return 0;
    return 1;
}

static int valid_filename(const char *s)
{
    return *s && !strchr(s, '/') && !strchr(s, '\\') && strcmp(s, "..") != 0 && strcmp(s, ".") != 0;
}

/* Run cmd and return its whole stdout as a NUL-terminated heap string, or NULL on failure. */
static char *run_capture(const char *cmd)
{
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return NULL;
    size_t cap = 1 << 16, len = 0;
    char *out = malloc(cap);
    if (!out) {
        pclose(pipe);
        return NULL;
    }
    size_t n;
    while ((n = fread(out + len, 1, cap - len - 1, pipe)) > 0) {
        len += n;
        if (cap - len < 2) {
            char *bigger = realloc(out, cap * 2);
            if (!bigger) {
                free(out);
                pclose(pipe);
                return NULL;
            }
            out = bigger;
            cap *= 2;
        }
    }
    out[len] = '\0';
    if (pclose(pipe) != 0) {
        free(out);
        return NULL;
    }
    return out;
}

static int get_inode_block_group(const char *device, const char *inode)
{
    char cmd[PATH_MAX_LEN];
    snprintf(cmd, sizeof cmd, "istat \"%s\" %s", device, inode);
    char *out = run_capture(cmd);
    if (!out) return -1;
    int group = -1;
    for (char *line = out; line && *line;) {
        char *nl = strchr(line, '\n');
        int g;
        if (sscanf(line, "Group: %d", &g) == 1) {
            group = g;
            break;
        }
        line = nl ? nl + 1 : NULL;
    }
    free(out);
    return group;
}

typedef struct {
    uint64_t *first, *last;
    char *valid;
    size_t cap;
} GroupRanges;

static void ranges_set(GroupRanges *r, size_t g, uint64_t a, uint64_t b)
{
    if (g >= r->cap) {
        size_t ncap = r->cap ? r->cap : 64;
        while (ncap <= g) ncap *= 2;
        r->first = realloc(r->first, ncap * sizeof(uint64_t));
        r->last = realloc(r->last, ncap * sizeof(uint64_t));
        r->valid = realloc(r->valid, ncap);
        if (!r->first || !r->last || !r->valid) {
            fprintf(stderr, "Out of memory\n");
            exit(1);
        }
        memset(r->valid + r->cap, 0, ncap - r->cap);
        r->cap = ncap;
    }
    r->first[g] = a;
    r->last[g] = b;
    r->valid[g] = 1;
}

/* Byte range to scan for data of block `group` (widened to its whole flex group when fsstat reports one). */
static int get_scan_byte_range(const char *device, int group, uint64_t *start, uint64_t *end, char *desc, size_t desc_cap)
{
    char cmd[PATH_MAX_LEN];
    snprintf(cmd, sizeof cmd, "fsstat \"%s\"", device);
    char *out = run_capture(cmd);
    if (!out) return 0;

    unsigned block_size = 0;
    long flex_size = 0;
    long cur_group = -1;
    GroupRanges r = {0};

    for (char *line = out; line && *line;) {
        char *nl = strchr(line, '\n');
        unsigned bs;
        long g, fx;
        unsigned long long a, b;
        if (sscanf(line, "Block Size: %u", &bs) == 1) {
            block_size = bs;
        } else if (sscanf(line, "Group: %ld:", &g) == 1 && strchr(line, ':') && strstr(line, "Group:") == line) {
            cur_group = g;
        } else if (cur_group >= 0 && sscanf(line, " Block Range: %llu - %llu", &a, &b) == 2) {
            ranges_set(&r, (size_t)cur_group, a, b);
            cur_group = -1; /* first range after a group header belongs to that group */
        } else if ((strstr(line, "Block Groups Per Flex Group:") || strstr(line, "Flex Block Group Size:")) &&
                   sscanf(strchr(line, ':') + 1, " %ld", &fx) == 1) {
            flex_size = fx;
        }
        line = nl ? nl + 1 : NULL;
    }
    free(out);

    int ok = 0;
    if (block_size && (size_t)group < r.cap && r.valid[group]) {
        uint64_t sb = r.first[group], eb = r.last[group];
        snprintf(desc, desc_cap, "block group %d", group);
        if (flex_size > 1) {
            long idx = group / flex_size;
            long lo = idx * flex_size, hi = lo + flex_size, count = 0, gmin = -1, gmax = -1;
            uint64_t fsb = 0, feb = 0;
            for (long g = lo; g < hi && (size_t)g < r.cap; g++) {
                if (!r.valid[g]) continue;
                if (count == 0 || r.first[g] < fsb) fsb = r.first[g];
                if (count == 0 || r.last[g] > feb) feb = r.last[g];
                if (gmin < 0) gmin = g;
                gmax = g;
                count++;
            }
            if (count > 1) {
                sb = fsb;
                eb = feb;
                snprintf(desc, desc_cap, "flex group %ld (block groups %ld-%ld)", idx, gmin, gmax);
            }
        }
        *start = (uint64_t)block_size * sb;
        *end = (uint64_t)block_size * (eb + 1);
        ok = 1;
    }
    free(r.first);
    free(r.last);
    free(r.valid);
    return ok;
}

/* Dự phòng cho qr: khi icat trả 0 byte (ext3/ext4 đã xóa con trỏ block của inode), dữ liệu
 * thật vẫn còn trên đĩa. Xác định inode thuộc block/flex group nào (istat + fsstat) rồi chạy
 * deep_recover với MỌI loại file, nhưng chỉ trong dải byte của group đó thay vì cả ổ. */
static int scoped_carve_by_inode(const char *device, const char *inode, const char *outdir)
{
    int group = get_inode_block_group(device, inode);
    if (group < 0) {
        printf("Could not determine the block group for inode %s (istat unavailable or inode gone).\n", inode);
        return 0;
    }
    uint64_t start, end;
    char desc[128];
    if (!get_scan_byte_range(device, group, &start, &end, desc, sizeof desc)) {
        printf("Could not determine the byte range of block group %d (fsstat unavailable).\n", group);
        return 0;
    }
    int all[N_TYPES];
    for (size_t i = 0; i < N_TYPES; i++) all[i] = (int)i;

    printf("icat returned no data for inode %s - its block pointers were likely cleared on delete (common on ext3/ext4).\n", inode);
    printf("Falling back to a signature scan of %s (%" PRIu64 "-%" PRIu64 " bytes), for all known file types, "
           "instead of the whole device...\n", desc, start, end);

    char prefix[64];
    snprintf(prefix, sizeof prefix, "inode%s_", inode);
    long found = deep_recover(device, outdir, all, N_TYPES, start, 1, end, prefix);
    if (found <= 0) {
        printf("No known file signature found in %s.\n", desc);
        printf("Either the data has already been overwritten, or it lives outside this scoped area.\n");
        printf("Next step: try a full scan - dr %s -f ", device);
        print_valid_types(stdout);
        return 0;
    }
    return 1;
}

/* icat <inode> -> outfile; returns bytes written or -1 on error. */
static long long icat_to_file(const char *device, const char *inode, const char *outfile)
{
    char cmd[PATH_MAX_LEN];
    snprintf(cmd, sizeof cmd, "icat \"%s\" %s", device, inode);
    FILE *pipe = popen(cmd, "rb");
    if (!pipe) return -1;
    FILE *f = open_out(outfile);
    char chunk[65536];
    long long total = 0;
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, pipe)) > 0) {
        fwrite(chunk, 1, n, f);
        total += (long long)n;
    }
    fclose(f);
    if (pclose(pipe) != 0) return -1;
    return total;
}

/* Khôi phục một inode: kiểm tra đầu vào -> icat ra file -> nếu file rỗng thì carve có phạm vi */
static int recover_one_inode(const char *device, const char *inode, const char *name, const char *outdir)
{
    if (!valid_inode(inode)) {
        fprintf(stderr, "Invalid inode '%s'\n", inode);
        return 0;
    }
    if (!valid_filename(name)) {
        fprintf(stderr, "Invalid output file name '%s' (no path separators allowed)\n", name);
        return 0;
    }
    char outfile[PATH_MAX_LEN];
    snprintf(outfile, sizeof outfile, "%s%c%s", outdir, PATH_SEP, name);
    long long bytes = icat_to_file(device, inode, outfile);
    if (bytes < 0) {
        fprintf(stderr, "icat failed for inode %s (is The Sleuth Kit installed and on PATH?)\n", inode);
        return 0;
    }
    printf("Wrote file: %s\n", outfile);
    if (bytes == 0) scoped_carve_by_inode(device, inode, outdir);
    return 1;
}

static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

static int quick_recover(const char *device, const char *outdir, char *inodes)
{
    if (!safe_arg(device)) {
        fprintf(stderr, "Device path contains characters that are not allowed for qr.\n");
        return 1;
    }
    if (!inodes) {
        char cmd[PATH_MAX_LEN];
        puts("Showing inode number of files:");
        snprintf(cmd, sizeof cmd, "fls -r \"%s\"", device);
        char *listing = run_capture(cmd);
        if (!listing) {
            fprintf(stderr, "fls failed (is The Sleuth Kit installed and on PATH?)\n");
            return 1;
        }
        for (char *line = listing; line && *line;) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            chomp(line);
            if (strchr(line, '*')) print_red(line); else puts(line);
            line = nl ? nl + 1 : NULL;
        }
        free(listing);

        char inode[64], name[512];
        printf("Enter the inode of the deleted file:  ");
        fflush(stdout);
        if (!fgets(inode, sizeof inode, stdin)) return 1;
        chomp(inode);
        if (!valid_inode(inode)) {
            fprintf(stderr, "Invalid inode.\n");
            return 1;
        }
        snprintf(cmd, sizeof cmd, "istat \"%s\" %s", device, inode);
        int rc = system(cmd);
        (void)rc;
        printf("Enter the name of the file where data to be stored (with extension): \n");
        fflush(stdout);
        if (!fgets(name, sizeof name, stdin)) return 1;
        chomp(name);
        return recover_one_inode(device, inode, name, outdir) ? 0 : 1;
    }

    int status = 0;
    for (char *item = strtok(inodes, ","); item; item = strtok(NULL, ",")) {
        char *colon = strchr(item, ':');
        if (!colon) {
            fprintf(stderr, "Bad inode spec '%s' (expected inode:filename)\n", item);
            status = 1;
            continue;
        }
        *colon = '\0';
        printf("Recovering inode: %s\n", item);
        if (!recover_one_inode(device, item, colon + 1, outdir)) status = 1;
    }
    return status;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(FILE *out)
{
    fprintf(out,
            "cforensics - C File Recovery Private Edition\n\n"
            "usage: cforensics <action> <device> [options]\n\n"
            "  action   dr: deep recovery for formatted, partitioned devices\n"
            "           qr: quick recovery for deleted files (needs The Sleuth Kit)\n"
            "  device   path to device or image. Ex: /dev/sda, disk.img, \\\\.\\PhysicalDrive1\n\n"
            "options:\n"
            "  -f, --file_types LIST   dr file types, comma separated [default=jpg]\n"
            "  -o, --output_path DIR   output directory [default=recovered]\n"
            "  -i, --inodes LIST       qr inodes. Ex: 12341:file1.doc,12342:file2.pdf\n"
            "  -v, --version           show version\n"
            "  -h, --help              show this help\n\n"
            "valid file types: ");
    print_valid_types(out);
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hout, &mode)) SetConsoleMode(hout, mode | 0x0004); /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
#endif
    const char *positional[2] = {NULL, NULL};
    int npos = 0;
    const char *file_types = "jpg";
    const char *outdir = "recovered";
    char *inodes = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("cforensics %s\n", VERSION);
            return 0;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(a, "-f") || !strcmp(a, "--file_types") || !strcmp(a, "-o") ||
                   !strcmp(a, "--output_path") || !strcmp(a, "-i") || !strcmp(a, "--inodes")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Option %s needs a value\n", a);
                return 2;
            }
            char *val = argv[++i];
            if (a[1] == 'f' || a[2] == 'f') file_types = val;
            else if (a[1] == 'o' || a[2] == 'o') outdir = val;
            else inodes = val;
        } else if (a[0] == '-' && a[1]) {
            fprintf(stderr, "Unknown option: %s\n", a);
            usage(stderr);
            return 2;
        } else if (npos < 2) {
            positional[npos++] = a;
        } else {
            fprintf(stderr, "Unexpected argument: %s\n", a);
            return 2;
        }
    }
    if (npos != 2) {
        usage(stderr);
        return 2;
    }
    const char *action = positional[0];
    const char *device = positional[1];

    if (strcmp(action, "dr") && strcmp(action, "qr")) {
        fprintf(stderr, "Unknown action '%s' (use dr or qr)\n", action);
        return 2;
    }
    if (*outdir) make_dir(outdir);

    if (!strcmp(action, "dr")) {
        char *copy = strdup(file_types);
        int types[N_TYPES];
        size_t ntypes = 0;
        int bad = 0;
        for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
            int idx = type_index(tok);
            if (idx < 0) {
                fprintf(stderr, "Unknown file type: %s\n", tok);
                bad = 1;
            } else if (ntypes < N_TYPES) {
                types[ntypes++] = idx;
            }
        }
        free(copy);
        if (bad || ntypes == 0) {
            fprintf(stderr, "Valid types: ");
            print_valid_types(stderr);
            return 2;
        }
        return deep_recover(device, outdir, types, ntypes, 0, 0, 0, "") < 0 ? 1 : 0;
    }
    return quick_recover(device, outdir, inodes);
}
