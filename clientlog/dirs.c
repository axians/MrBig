#include "arena.h"
#include "clientlog.h"
#include <fileapi.h>
#include <minwindef.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winioctl.h>
#include <winnt.h>
#include <winscard.h>


#define DIRS_MAX_SIZE 5000000

#define DIRS_HASH_EMPTY ((uint64_t)-1)

typedef struct {
    uint64_t *buckets;
    uint64_t capacity;
} PathIndexMap;

typedef struct {
    char path[MAX_PATH * 4];
    uint64_t size;
    FILETIME last_write;
    BOOLEAN is_folder;
    BOOLEAN scanned;
    BOOLEAN deleted;
} DirCacheEntry;

typedef struct {
    DirCacheEntry *entries;
    uint64_t length;
    uint64_t capacity;

    PathIndexMap map;
} DirCache;

static uint64_t hash_path(const char *s) {
    uint64_t h = 1469598103934665603ULL;

    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }

    return h;
}

void map_resize(PathIndexMap *m, const DirCache *cache) {
    size_t old_capacity = m->capacity;
    uint64_t *old_buckets = m->buckets;

    size_t new_capacity = old_capacity ? old_capacity * 2 : 1024;

    uint64_t *new_buckets = malloc(new_capacity * sizeof(*new_buckets));

    if (!new_buckets) {
        fprintf(stderr, "map_resize: out of memory\n");
        exit(1);
    }

    for (size_t i = 0; i < new_capacity; i++)
        new_buckets[i] = DIRS_HASH_EMPTY;

    m->buckets = new_buckets;
    m->capacity = new_capacity;

    for (size_t i = 0; i < old_capacity; i++) {

        if (old_buckets[i] == DIRS_HASH_EMPTY)
            continue;

        uint64_t index = old_buckets[i];

        /* Rehash using the path stored in the cache */
        const char *path = cache->entries[index].path;

        uint64_t h = hash_path(path);
        size_t pos = h % m->capacity;

        while (m->buckets[pos] != DIRS_HASH_EMPTY)
            pos = (pos + 1) % m->capacity;

        m->buckets[pos] = index;
    }

    free(old_buckets);
}
void map_init(PathIndexMap *m, uint64_t cap) {
    m->capacity = cap;
    m->buckets = malloc(cap * sizeof(uint64_t));

    for (uint64_t i = 0; i < cap; i++)
        m->buckets[i] = DIRS_HASH_EMPTY;
}
DirCacheEntry *map_find(DirCache *m, const char *path) {
    uint64_t h = hash_path(path);
    uint64_t i = h % m->capacity;

    while (m->map.buckets[i] != DIRS_HASH_EMPTY) {
        uint64_t idx = m->map.buckets[i];

        DirCacheEntry *entry = &m->entries[idx];

        if (strcmp(entry->path, path) == 0)

            return entry;

        i = (i + 1) % m->map.capacity;
    }

    return NULL;
}
void map_set(PathIndexMap *m, DirCache *cache, const char *path, uint64_t index) {
    // resize BEFORE probing
    if ((cache->length + 1) * 100 / m->capacity > 70)
        map_resize(m, cache);

    uint64_t h = hash_path(path);
    uint64_t i = h % m->capacity;

    size_t probes = 0;

    while (m->buckets[i] != DIRS_HASH_EMPTY) {

        uint64_t existing_index = m->buckets[i];

        if (_stricmp(cache->entries[existing_index].path, path) == 0) {
            m->buckets[i] = index; // optional update
            return;
        }

        if (++probes > m->capacity) {
            printf("HASH LOOP DETECTED: %s\n", path);
            return;
        }

        i = (i + 1) % m->capacity;
    }

    m->buckets[i] = index;
}

DirCacheEntry *dir_cache_find(DirCache *c, const char *path) {
    uint64_t h = hash_path(path);
    uint64_t i = h % c->map.capacity;
    size_t probes = 0;
    while (c->map.buckets[i] != DIRS_HASH_EMPTY) {
        uint64_t idx = c->map.buckets[i];
        if (++probes > c->map.capacity) {

            printf("HASH LOOP DETECTED: %s\n", path);
            return NULL;
        }
        if (strcmp(c->entries[idx].path, path) == 0)
            return &c->entries[idx];

        i = (i + 1) % c->map.capacity;
    }

    return NULL;
}
DirCacheEntry *dir_cache_insert(DirCache *c, DirCacheEntry e) {
    // grow array
    if (c->length == c->capacity) {
        c->capacity = c->capacity ? c->capacity * 2 : 1024;
        c->entries = realloc(c->entries, c->capacity * sizeof(*c->entries));
    }
    if ((c->length + 1) * 100 / c->map.capacity > 70)
        map_resize(&c->map, c);

    uint64_t index = c->length++;
    c->entries[index] = e;

    // insert into hash map
    uint64_t h = hash_path(e.path);
    uint64_t i = h % c->map.capacity;

    while (c->map.buckets[i] != DIRS_HASH_EMPTY)
        i = (i + 1) % c->map.capacity;

    c->map.buckets[i] = index;

    return &c->entries[index];
}

void dir_cache_print(const DirCache *cache, int from, int to) {

    printf("Entries: %llu\n", cache->length);

    if (to == -1 || to > cache->length)
        to = cache->length;
    for (uint64_t i = from; i < to; i++) {
        const DirCacheEntry *entry = &cache->entries[i];

        printf("[%llu]\n"
               "  Path: %s\n"
               "  Type: %s\n"
               "  Size: %llu\n"
               "  Last Write: %lu:%lu\n\n",
               i, entry->path, entry->is_folder ? "Folder" : "File", entry->size,
               entry->last_write.dwHighDateTime, entry->last_write.dwLowDateTime);
    }
}
void dir_cache_init(DirCache *c) {
    c->entries = NULL;
    c->length = 0;
    c->capacity = 0;

    map_init(&c->map, 4096); // power of 2 recommended
}

int dir_cache_push(DirCache *cache, DirCacheEntry entry) {
    printf("length: %llu, cap: %llu\n", cache->length, cache->capacity);
    if (cache->length == cache->capacity) {
        // make bigger
        uint64_t new_capacity = cache->capacity ? cache->capacity * 2 : 128;

        if (new_capacity > DIRS_MAX_SIZE / sizeof(*cache->entries)) {
            printf("new Capacity (%llu) > DIRS_MAX_SIZE\n", new_capacity);

            return 0; // Will excede max capacity
        }

        DirCacheEntry *new_entires =
            realloc(cache->entries, new_capacity * sizeof(*cache->entries));

        if (!new_entires) {
            printf("Could not alloc new entries\n");

            return 0; // could not realloc
        }

        cache->entries = new_entires;
        cache->capacity = new_capacity;
    }
    cache->entries[cache->length++] = entry;
    return 1;
}

void dir_cache_free(DirCache *cache) {
    free(cache->entries);

    cache->entries = NULL;
    cache->length = 0;
    cache->capacity = 0;
}
/* static FILETIME get_dir_time(const WIN32_FIND_DATAA *data) { return data->ftLastWriteTime; } */

static uint64_t file_size_from_find_data(WIN32_FIND_DATAA *data) {
    return ((uint64_t)data->nFileSizeHigh << 32) | (uint64_t)data->nFileSizeLow;
}

static int is_dot_dir(const char *name) {
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

static int join_path(char *out, uint64_t out_size, const char *base, const char *name) {
    uint64_t base_len = strlen(base);
    uint64_t name_len = strlen(name);

    int needs_slash = base_len > 0 && base[base_len - 1] != '\\' && base[base_len - 1] != '/';

    uint64_t needed = base_len + (needs_slash ? 1 : 0) + name_len + 1;

    if (needed > out_size) {
        return 0;
    }

    memcpy(out, base, base_len);

    uint64_t pos = base_len;

    if (needs_slash) {
        out[pos++] = '\\';
    }

    memcpy(out + pos, name, name_len);
    out[pos + name_len] = '\0';

    return 1;
}

int dirs_write_file_cache(const DirCache *cache) {

    FILE *file;
    printf("Opening file\n");
    file = fopen("dirs.cache", "wb");
    printf("Opened file\n");

    if (file == NULL) {
        printf("Failed to open cache file for writing.\n");
        return 0;
    }
    printf("Not null\n");

    if (fwrite(&cache->length, sizeof(uint64_t), 1, file) != 1) {
        printf("Failed to write cache file.\n");
        fclose(file);
        return 0;
    }
    printf("Got length\n");

    if (fwrite(cache->entries, sizeof(DirCacheEntry), cache->length, file) != cache->length) {
        printf("Failed to write cache entries to file.\n");
        fclose(file);
        return 0;
    }
    printf("Successfully wrote %llu cache entries to file.\n", cache->length);

    fclose(file);
    return 1;
}

int dirs_load_file_cache(DirCache *cache) {

    // file format is:
    // <path> <is_folder> <bytes> <last_write (unix epoch)> \n
    FILE *f = fopen("dirs.cache", "rb");
    if (!f)
        return 0;
    uint64_t count;

    if (fread(&count, sizeof(uint64_t), 1, f) != 1) {
        printf("Failed to read cache count from file.\n");
        fclose(f);
        return 0;
    }

    DirCacheEntry *entries = malloc(count * sizeof(DirCacheEntry));
    if (!entries) {
        fclose(f);
        return 0;
    }

    if (fread(entries, sizeof(DirCacheEntry), count, f) != count) {
        printf("Failed to read cache entries from file.\n");
        free(entries);
        fclose(f);
        return 0;
    }

    free(cache->entries);
    cache->entries = entries;
    cache->length = count;
    cache->capacity = count;

    if (fclose(f) != 0) {
        printf("Failed to close cache file after reading.\n");
        return 0;
    }

    return 1;
}

uint64_t scan_dir(DirCache *cache, const char *base_path, int depth, int max_depth) {
    if (depth > max_depth)
        return 0;

    if (_strcmpi(base_path, "C:\\Windows\\System32") == 0 ||
        _strcmpi(base_path, "C:\\Windows\\SysWOW64") == 0 ||
        _strcmpi(base_path, "C:\\Windows\\WinSxS") == 0)
        return 0;

    char search[MAX_PATH * 4];
    snprintf(search, sizeof(search), "%s\\*", base_path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);

    if (h == INVALID_HANDLE_VALUE)
        return 0;

    uint64_t total_size = 0;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full[MAX_PATH * 4];
        snprintf(full, sizeof(full), "%s\\%s", base_path, fd.cFileName);

        DWORD attrs = fd.dwFileAttributes;

        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (attrs & FILE_ATTRIBUTE_SYSTEM)
            continue;

        uint64_t size = 0;

        if (attrs & FILE_ATTRIBUTE_DIRECTORY) {

            size = scan_dir(cache, full, depth + 1, max_depth);

        } else {

            size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        }

        total_size += size;

        // cache insert/update only for identity, NOT size logic
        DirCacheEntry *entry = dir_cache_find(cache, full);

        if (!entry) {
            DirCacheEntry e = {0};

            strncpy(e.path, full, sizeof(e.path) - 1);
            e.is_folder = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
            e.size = size;
            e.scanned = 1;

            dir_cache_insert(cache, e);
        }

    } while (FindNextFileA(h, &fd));

    FindClose(h);

    return total_size;
}

/* uint64_t scan_dir(DirCache *cache, const char *base_path, int depth, int max_depth) { */
/*     if (depth > max_depth) { */
/*         return 0; */
/*     } */
/*     if (_strcmpi(base_path, "C:\\Windows\\System32") == 0 || */
/*         _strcmpi(base_path, "C:\\Windows\\SysWOW64") == 0 || */
/*         _strcmpi(base_path, "C:\\Windows\\WinSxS") == 0) { */
/*         return 0; */
/*     } */
/**/
/*     char search[MAX_PATH * 4]; */
/*     snprintf(search, sizeof(search), "%s\\*", base_path); */
/**/
/*     WIN32_FIND_DATAA fd; */
/*     HANDLE h = FindFirstFileA(search, &fd); */
/**/
/*     do { */
/**/
/*         if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) */
/*             continue; */
/*         char full[MAX_PATH * 4]; */
/*         snprintf(full, sizeof(full), "%s\\%s", base_path, fd.cFileName); */
/**/
/*         DWORD attrs = fd.dwFileAttributes; */
/**/
/*         if (h == INVALID_HANDLE_VALUE) */
/*             continue; */
/*         if (attrs == INVALID_FILE_ATTRIBUTES) */
/*             continue; */
/**/
/*         if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) */
/*             continue; */
/**/
/*         if (attrs & FILE_ATTRIBUTE_SYSTEM) */
/*             continue; */
/**/
/*         DirCacheEntry *entry = dir_cache_find(cache, full); */
/**/
/*         // 2. create if missing */
/*         if (!entry) { */
/*             DirCacheEntry e = {0}; */
/**/
/*             strncpy(e.path, full, sizeof(e.path) - 1); */
/*             e.is_folder = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0; */
/*             e.size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow; */
/*             e.last_write = fd.ftLastWriteTime; */
/*             e.scanned = 0; */
/**/
/*             entry = dir_cache_insert(cache, e); */
/*         } */
/**/
/*         if (entry->is_folder && */
/**/
/*             !(fd.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_SYSTEM)) && */
/*             depth <= max_depth && !entry->scanned) */
/**/
/*         { */
/**/
/*             entry->scanned = 1; */
/**/
/*             scan_dir(cache, full, depth + 1, max_depth); */
/*         } */
/**/
/*     } while (FindNextFileA(h, &fd)); */
/**/
/*     FindClose(h); */
/*     return 0; */
/* } */

void clog_dirs(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "\n[dirs]\n");

    DirCache cache = {0};
    dir_cache_init(&cache);

    int success = dirs_load_file_cache(&cache);

    printf("Loaded entries: %llu\n", cache.length);

    uint64_t old_length = cache.length;

    int max_depth = 20;

    if (!success) {
        printf("No cache found, scanning...\n");

        scan_dir(&cache, "C:", 0, max_depth);
        printf("Writing cache\n");

    } else {
        printf("Cache loaded, rebuilding hash map...\n");
        for (size_t i = 0; i < cache.length; i++) {

            map_set(&cache.map,

                    &cache,

                    cache.entries[i].path,

                    i);
        }
        printf("Hash map rebuilt.\n");
        printf("Testing lookup for C:\\Windows\\write.exe...\n");

        DirCacheEntry *e = dir_cache_find(&cache, "C:\\Windows\\write.exe");

        if (e)
            printf("FOUND IN LOADED CACHE\n");
        else
            printf("NOT FOUND (hash not rebuilt)\n");

        printf("Loaded cache with %llu entries\n", cache.length);
        for (int i = 0; i < cache.length; i++) {
            DirCacheEntry entry = cache.entries[i];
            scan_dir(&cache, entry.path, 0, max_depth);
        }
    }
    printf("Writing cache (%llu)\n", cache.length);
    success = dirs_write_file_cache(&cache);
    if (success) {
        printf("Scan complete, cache saved with %llu entries.\n", cache.length);

    } else {
        printf("Could not save cache correctly\n");
    }

    dir_cache_print(&cache, 0, 10);
    dir_cache_free(&cache);
}
#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_dirs(st->Memory);
    clog_PopDeferAll(&st->Memory);
    printf("%s", st->Start);
}
#endif
