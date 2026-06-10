#include "arena.h"
#include "clientlog.h"
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <winioctl.h>

#define MAX_DIR_RESULTS 1000
#define CHILD_RATIO_THRESHOLD 0.9

typedef struct DirSize {
    char path[MAX_PATH * 4];
    uint64_t size;
    size_t largest_child_size;
} DirSize;

typedef struct DirResults {
    DirSize items[MAX_DIR_RESULTS];
    size_t count;
} DirResults;

static void add_dir_result(DirResults *results, const char *path, uint64_t size, uint64_t largest_child_size) {
    if (results->count >= MAX_DIR_RESULTS) {
        return;
    }

    DirSize *item = &results->items[results->count++];

    snprintf(item->path, sizeof(item->path), "%s", path);
    item->size = size;
    item->largest_child_size = largest_child_size;
}

static int compare_dir_size_desc(const void *a, const void *b) {
    const DirSize *da = (const DirSize *)a;
    const DirSize *db = (const DirSize *)b;

    if (da->size < db->size)
        return 1;
    if (da->size > db->size)
        return -1;
    return 0;
}

static void clog_top_dirs(clog_Arena *scratch, DirResults *results, size_t top_n) {
    qsort(results->items, results->count, sizeof(results->items[0]), compare_dir_size_desc);

    size_t limit = results->count < top_n ? results->count : top_n;

    for (size_t i = 0; i < limit; i++) {
        clog_ArenaAppend(scratch, "%2zu. %8.2f MB  %s\n", i + 1,
                         results->items[i].size / 1024.0 / 1024.0, results->items[i].path);

    }
}

static int is_wrapper_dir(const DirSize *dir) {

    if (dir->size == 0 || dir->largest_child_size == 0) {
        return 0;
    }

    double child_ratio = (double)dir->largest_child_size / (double)dir->size;
    return child_ratio > CHILD_RATIO_THRESHOLD;
}
static void clog_top_dirs_no_children(clog_Arena *scratch, DirResults *results, size_t top_n) {
    qsort(results->items, results->count, sizeof(results->items[0]), compare_dir_size_desc);

    size_t printed_count = 0;

    for (size_t i = 0; i < results->count && printed_count < top_n; i++) {
        DirSize *candidate = &results->items[i];

        if (is_wrapper_dir(candidate)) {
            continue;
        }

        printed_count++;

        clog_ArenaAppend(scratch, "%2zu. %8.2f MB  %s\n", printed_count,
                         candidate->size / 1024.0 / 1024.0, candidate->path);
    }
}

static uint64_t file_size_from_find_data(WIN32_FIND_DATAA *data) {
    return ((uint64_t)data->nFileSizeHigh << 32) | (uint64_t)data->nFileSizeLow;
}

static int is_dot_dir(const char *name) {
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}
static int join_path(char *out, size_t out_size, const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);

    int needs_slash =
        base_len > 0 &&
        base[base_len - 1] != '\\' &&
        base[base_len - 1] != '/';

    size_t needed = base_len + (needs_slash ? 1 : 0) + name_len + 1;

    if (needed > out_size) {
        return 0;
    }

    memcpy(out, base, base_len);

    size_t pos = base_len;

    if (needs_slash) {
        out[pos++] = '\\';
    }

    memcpy(out + pos, name, name_len);
    out[pos + name_len] = '\0';

    return 1;
}

uint64_t recurse_path(const char *path, int depth, DirResults *results) {
    char search_path[MAX_PATH * 4];
    if (!join_path(search_path, sizeof(search_path), path, "*")) {
        fprintf(stderr, "Path too long: %s\n", path);
        return 0;
    }
    /* snprintf(search_path, sizeof(search_path), "%s\\*", path); */

    WIN32_FIND_DATAA data;

    HANDLE h = FindFirstFileExA(search_path, FindExInfoBasic, &data, FindExSearchNameMatch, NULL,
                                FIND_FIRST_EX_LARGE_FETCH);

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();

        if (err != ERROR_ACCESS_DENIED) {
            fprintf(stderr, "Could not open %s, error %lu\n", path, err);
        }

        return 0;
    }

    uint64_t total = 0;
    uint64_t largest_child_size = 0;

    do {
        if (is_dot_dir(data.cFileName)) {
            continue;
        }

        char child_path[MAX_PATH * 4];
        if (!join_path(child_path, sizeof(child_path), path, data.cFileName)) {
            fprintf(stderr, "Path too long: %s\n", path);
            continue;
        }
        /* snprintf(child_path, sizeof(child_path), "%s\\%s", path, data.cFileName); */

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                continue;
            }

            uint64_t child_size = recurse_path(child_path, depth + 1, results);
            total += child_size;
            if (child_size > largest_child_size) {
                largest_child_size = child_size;
            }
        } else {
            total += file_size_from_find_data(&data);
        }

    } while (FindNextFileA(h, &data));

    FindClose(h);

    /* printf("%*s%s -> %.2f MB\n", depth * 2, "", path, total / 1024.0 / 1024.0); */
    add_dir_result(results, path, total, largest_child_size);

    return total;
}
void clog_dirs(clog_Arena scratch) {
    DirResults results = {0};

    clog_ArenaAppend(&scratch, "\n[dirs_filter_childred]\n"); // goes further down

    recurse_path("C:\\", 0, &results);
    clog_top_dirs_no_children(&scratch, &results, 10);
    clog_ArenaAppend(&scratch, "\n[dirs]\n"); // goes further down

    clog_top_dirs(&scratch, &results, 10);
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_dirs(st->Memory);
    clog_PopDeferAll(&st->Memory);
    printf("%s", st->Start);
}
#endif
