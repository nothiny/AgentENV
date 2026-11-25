// Generation log for checking that a fork child's memory and volume come
// from the same instant.
//
//   genlog write <log> <pidfile> <interval_us>
//       Appends 1, 2, 3, ... to <log>, one record per generation. A record
//       is one 4 KiB page: the number, spaces, a newline. Each is a single
//       write followed by fsync, and the counter lives only in this
//       process's memory. Writes its pid to <pidfile> first.
//   genlog check <log>
//       Drops the file's cached pages, so the volume's own contents are read
//       back, then checks the lines are exactly 1..N. Prints "ok <N>" and
//       exits 0, or prints where the sequence breaks and exits 1.
//
// A child restored from memory taken at B on a volume sealed at an earlier
// A carries on from B+1 after A: its log has a gap (or, once its cached
// pages are dropped, garbage where it believed lines were). A child whose
// memory and volume match keeps a gapless log however long it runs.
//
// Records fill whole pages because a VM child keeps the log's pages in its
// own page cache: writing back the page it appends to would copy the
// remembered lines of that page onto its volume and hide a gap inside it.
// With one record per page, the pages of a gap are never written again.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RECORD 4096

static void die(const char *what)
{
    perror(what);
    exit(2);
}

static void write_pid(const char *path)
{
    char value[32];
    int length = snprintf(value, sizeof(value), "%ld\n", (long)getpid());
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0 || write(fd, value, length) != length || fsync(fd) || close(fd))
        die(path);
}

__attribute__((noreturn)) static void write_log(const char *log, const char *pidfile,
                                               long interval_us)
{
    int fd = open(log, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0)
        die(log);
    write_pid(pidfile);
    struct timespec delay = {.tv_sec = interval_us / 1000000,
                             .tv_nsec = (interval_us % 1000000) * 1000};
    char record[RECORD];
    for (uint64_t generation = 1;; generation++) {
        memset(record, ' ', RECORD - 1);
        record[RECORD - 1] = '\n';
        int digits = snprintf(record, RECORD, "%" PRIu64, generation);
        record[digits] = ' ';
        if (write(fd, record, RECORD) != RECORD)
            die("write");
        if (fsync(fd))
            die("fsync");
        if (interval_us > 0) {
            struct timespec left = delay;
            while (nanosleep(&left, &left) == -1)
                if (errno != EINTR)
                    die("nanosleep");
        }
    }
}

static int check_log(const char *log)
{
    int fd = open(log, O_RDONLY);
    if (fd < 0)
        die(log);
    // Read what the volume holds, not what this kernel remembers writing.
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    struct stat st;
    if (fstat(fd, &st))
        die("fstat");
    char *data = malloc(st.st_size + 1);
    if (!data)
        die("malloc");
    off_t got = 0;
    while (got < st.st_size) {
        ssize_t n = read(fd, data + got, st.st_size - got);
        if (n < 0)
            die("read");
        if (n == 0)
            break;
        got += n;
    }
    uint64_t expected = 1;
    off_t line_start = 0;
    for (off_t i = 0; i < got; i++) {
        if (data[i] == '\n') {
            if (i == line_start) {
                printf("empty line at byte %jd after %" PRIu64 "\n", (intmax_t)i, expected - 1);
                return 1;
            }
            uint64_t value = 0;
            off_t j = line_start;
            for (; j < i && data[j] != ' '; j++)
                value = value * 10 + (uint64_t)(data[j] - '0');
            if (j == line_start) {
                printf("no number at byte %jd after %" PRIu64 "\n", (intmax_t)line_start,
                       expected - 1);
                return 1;
            }
            if (value != expected) {
                printf("gap: %" PRIu64 " follows %" PRIu64 " at byte %jd\n", value,
                       expected - 1, (intmax_t)line_start);
                return 1;
            }
            expected++;
            line_start = i + 1;
        } else if (data[i] == ' ' && i > line_start) {
            // Padding: only after the number.
            if (data[i - 1] != ' ' && (data[i - 1] < '0' || data[i - 1] > '9')) {
                printf("bad padding at %jd after %" PRIu64 "\n", (intmax_t)i, expected - 1);
                return 1;
            }
        } else if (data[i] < '0' || data[i] > '9' ||
                   (i > line_start && data[i - 1] == ' ')) {
            printf("bad byte 0x%02x at %jd after %" PRIu64 "\n", (unsigned char)data[i],
                   (intmax_t)i, expected - 1);
            return 1;
        }
    }
    if (line_start != got) {
        printf("unterminated line at byte %jd after %" PRIu64 "\n", (intmax_t)line_start,
               expected - 1);
        return 1;
    }
    if (got != st.st_size) {
        printf("short read: %jd of %jd bytes\n", (intmax_t)got, (intmax_t)st.st_size);
        return 1;
    }
    printf("ok %" PRIu64 "\n", expected - 1);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "write"))
        write_log(argv[2], argv[3], strtol(argv[4], NULL, 10));
    if (argc == 3 && !strcmp(argv[1], "check"))
        return check_log(argv[2]);
    fprintf(stderr, "usage: genlog write <log> <pidfile> <interval_us> | genlog check <log>\n");
    return 2;
}
