#include "arena.h"
#include "clientlog.h"
#include <fileapi.h>
#include <stdint.h>
#include <winnt.h>
#include <winscard.h>

#define DIRS_MAX_SIZE 5000000

#define DIRS_HASH_EMPTY ((uint64_t)-1)

#define DIRS_INVALID 0xFFFFFFFFu

#define DIRS_TOP_N 20

typedef struct {
    uint32_t parent;
    uint32_t first_child;
    uint32_t next_sibling;

    uint32_t name_offset;
    uint16_t name_len;

    uint64_t direct_size;
    uint64_t total_size;
    uint64_t largest_descendant;
} DirEntry;

typedef struct {
    uint32_t dir_idx;
    char path[MAX_PATH * 4];
} StackItem;

typedef struct {
    StackItem *items;
    uint32_t size;
    uint32_t cap;
} Stack;

typedef struct {
    DirEntry *dirs;
    uint32_t dir_count;
    uint32_t dir_cap;

    char *pool;
    uint32_t pool_size;
    uint32_t pool_cap;
} ScanCtx;

typedef struct {
    uint32_t idx;
    uint64_t size;
} TopEntry;

typedef struct {
    TopEntry items[DIRS_TOP_N];
    uint32_t count;
} TopDirs;

static void dirs_top_add(TopDirs *t, uint32_t idx, uint64_t size) {
    // ignore empty
    if (size == 0)
        return;

    TopEntry e = {idx, size};

    // still space
    if (t->count < DIRS_TOP_N) {
        t->items[t->count++] = e;
        return;
    }

    // find smallest in current top
    uint32_t min_i = 0;
    for (uint32_t i = 1; i < DIRS_TOP_N; i++) {
        if (t->items[i].size < t->items[min_i].size)
            min_i = i;
    }

    // only replace if bigger
    if (size > t->items[min_i].size)
        t->items[min_i] = e;
}

static int dirs_is_useful(ScanCtx *c, uint32_t i) {
    uint64_t total = c->dirs[i].total_size;
    uint64_t big = c->dirs[i].largest_descendant;

    if (total == 0)
        return 0;

    double r = (double)big / (double)total;

    return r < 0.85;
}

void dirs_collect_top(ScanCtx *c, TopDirs *t) {
    t->count = 0;

    for (uint32_t i = 0; i < c->dir_count; i++) {
        if (!dirs_is_useful(c, i)) // try to filter dirs smartly
            continue;
        if (c->dirs[i].parent == DIRS_INVALID) // ignore root disk path like C:
            continue;

        dirs_top_add(t, i, c->dirs[i].total_size);
    }
}
void dirs_print_path(ScanCtx *c, uint32_t idx, clog_Arena *arena) {
    uint32_t stack[128];
    int depth = 0;

    while (idx != 0xFFFFFFFF) {
        stack[depth++] = idx;
        idx = c->dirs[idx].parent;
    }

    for (int i = depth - 1; i >= 0; i--) {
        uint32_t id = stack[i];
        char *name = c->pool + c->dirs[id].name_offset;

        clog_ArenaAppend(arena, "%s", name);

        if (i != 0) {
            clog_ArenaAppend(arena, "\\");
        }
    }
}

static void dirs_push(Stack *s, StackItem it) {
    if (s->size == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 1024;
        s->items = realloc(s->items, s->cap * sizeof(StackItem));
    }
    s->items[s->size++] = it;
}

static StackItem dirs_pop(Stack *s) { return s->items[--s->size]; }
static uint32_t dirs_pool_add_utf8(ScanCtx *c, const char *s) {
    uint32_t len = (uint32_t)strlen(s) + 1;

    while (c->pool_size + len > c->pool_cap) {
        c->pool_cap = c->pool_cap ? c->pool_cap * 2 : (1 << 20);
    }
    c->pool = realloc(c->pool, c->pool_cap);

    uint32_t offset = c->pool_size;
    memcpy(c->pool + c->pool_size, s, len);
    c->pool_size += len;

    return offset;
}

static uint32_t dirs_add_dir(ScanCtx *c, uint32_t parent, const char *name) {
    if (c->dir_count == c->dir_cap) {
        c->dir_cap = c->dir_cap ? c->dir_cap * 2 : 65536;
        c->dirs = realloc(c->dirs, c->dir_cap * sizeof(DirEntry));
    }

    uint32_t idx = c->dir_count++;

    c->dirs[idx].parent = parent;
    c->dirs[idx].first_child = 0xFFFFFFFF;
    c->dirs[idx].next_sibling = 0xFFFFFFFF;

    c->dirs[idx].direct_size = 0;
    c->dirs[idx].total_size = 0;

    c->dirs[idx].name_offset = dirs_pool_add_utf8(c, name);
    c->dirs[idx].name_len = (uint16_t)strlen(name);

    return idx;
}
static int dirs_path_join(char *dst, size_t cap, const char *a, const char *b) {
    size_t na = strlen(a);
    size_t nb = strlen(b);

    if (na + 1 + nb + 1 > cap)
        return 0;

    memcpy(dst, a, na);
    dst[na] = '\\';
    memcpy(dst + na + 1, b, nb + 1);

    return 1;
}

static int dirs_path_glob(char *dst, size_t cap, const char *base) {
    size_t n = strlen(base);

    if (n + 3 > cap)
        return 0;

    memcpy(dst, base, n);
    dst[n] = '\\';
    dst[n + 1] = '*';
    dst[n + 2] = '\0';

    return 1;
}

uint32_t dirs_scan_drive(ScanCtx *c, const char *root_path) {
    Stack st = {0};

    uint32_t root = dirs_add_dir(c, 0xFFFFFFFF, root_path);

    dirs_push(&st, (StackItem){.dir_idx = root});

    strcpy(st.items[0].path, root_path);

    st.size = 1;

    while (st.size > 0) {
        StackItem cur = dirs_pop(&st);
        uint32_t parent = cur.dir_idx;

        char search[MAX_PATH * 4];

        if (!dirs_path_glob(search, sizeof(search), cur.path))
            continue;

        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(search, &fd);

        if (h == INVALID_HANDLE_VALUE)
            continue;

        do {
            if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
                continue;

            char full[MAX_PATH * 4];

            if (!dirs_path_join(full, sizeof(full), cur.path, fd.cFileName))
                continue;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {

                if (_stricmp(fd.cFileName, "System32") == 0 ||
                    _stricmp(fd.cFileName, "sysWOW64") == 0 ||
                    _stricmp(fd.cFileName, "WinSxS") == 0) {
                    continue;
                }
                uint32_t child = dirs_add_dir(c, parent, fd.cFileName);

                // link sibling list
                c->dirs[child].next_sibling = c->dirs[parent].first_child;

                c->dirs[parent].first_child = child;

                dirs_push(&st, (StackItem){.dir_idx = child});

                strcpy(st.items[st.size - 1].path, full);
            } else {
                uint64_t size =
                    ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

                c->dirs[parent].direct_size += size;
            }

        } while (FindNextFileA(h, &fd));

        FindClose(h);
    }

    free(st.items);
    return root;
}
uint32_t dirs_scanctx_add_root(ScanCtx *c, const char *root_path) {
    return dirs_add_dir(c, 0xFFFFFFFF, root_path);
}
void dirs_scanctx_reserve(ScanCtx *c, uint32_t dirs, uint32_t pool_bytes) {
    c->dir_cap = dirs;
    c->dirs = malloc(dirs * sizeof(DirEntry));

    c->pool_cap = pool_bytes;
    c->pool = malloc(pool_bytes);
}
void dirs_scanctx_init(ScanCtx *c) {
    memset(c, 0, sizeof(*c));

    c->dirs = NULL;
    c->dir_count = 0;
    c->dir_cap = 0;

    c->pool = NULL;
    c->pool_size = 0;
    c->pool_cap = 0;
}
void dirs_scanctx_deinit(ScanCtx *c) {
    if (!c)
        return;

    free(c->dirs);
    free(c->pool);

    c->dirs = NULL;
    c->pool = NULL;

    c->dir_count = 0;
    c->dir_cap = 0;

    c->pool_size = 0;
    c->pool_cap = 0;
}

void dirs_aggregate(ScanCtx *c, uint32_t idx) {
    DirEntry *d = &c->dirs[idx];

    uint64_t total = d->direct_size;
    uint64_t largest = 0;

    for (uint32_t child = d->first_child; child != 0xFFFFFFFF;
         child = c->dirs[child].next_sibling) {

        dirs_aggregate(c, child);

        DirEntry *ch = &c->dirs[child];

        total += ch->total_size;

        if (ch->total_size > largest)
            largest = ch->total_size;

        if (ch->largest_descendant > largest)
            largest = ch->largest_descendant;
    }

    d->total_size = total;
    d->largest_descendant = largest;
}

void dirs_print_top(ScanCtx *c, TopDirs *t, clog_Arena *arena) {
    // sort biggest first
    for (uint32_t i = 0; i < t->count; i++)
        for (uint32_t j = i + 1; j < t->count; j++) {
            if (t->items[j].size > t->items[i].size) {
                TopEntry tmp = t->items[i];
                t->items[i] = t->items[j];
                t->items[j] = tmp;
            }
        }

    for (uint32_t i = 0; i < t->count; i++) {
        uint32_t idx = t->items[i].idx;

        CHAR bytes[16];
        clog_utils_PrettyBytes(t->items[i].size, 0, bytes);

        clog_ArenaAppend(arena, "%2u. %s  ", i + 1, bytes);

        dirs_print_path(c, idx, arena);

        clog_ArenaAppend(arena, "\n");
    }
}

void clog_dirs(clog_Arena scratch) {

    ScanCtx ctx;

    dirs_scanctx_init(&ctx);

    // optional but recommended for large disks
    dirs_scanctx_reserve(&ctx, 1000000, 64 * 1024 * 1024);

    dirs_scanctx_add_root(&ctx, "C:");

    uint32_t root = dirs_scan_drive(&ctx, "C:");

    TopDirs top20 = {0};

    dirs_aggregate(&ctx, root);
    dirs_collect_top(&ctx, &top20);

    // output to clientlog

    clog_ArenaAppend(&scratch, "[dirs]\n");
    dirs_print_top(&ctx, &top20, &scratch);

    // free and deinit
    dirs_scanctx_deinit(&ctx);
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_dirs(st->Memory);
    clog_PopDeferAll(&st->Memory);
    printf("%s", st->Start);
}
#endif
