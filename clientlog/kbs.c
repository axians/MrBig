#include "clientlog.h"
#include <initguid.h>
#include <wuapi.h>

typedef struct TreeSet {
    struct TreeSet *Left;
    struct TreeSet *Right;
    DWORD Value;
} TreeSet;

struct ComString {
    UINT32 len;
    wchar_t content[1];
};

DWORD kbs_ExtractKBNumber(wchar_t *title) {
    DWORD res = 0;
    BYTE *titleBytes = (BYTE *)title;
    int i = 0;
    while (titleBytes[i] != '\0') {
        i += 2;
        if (titleBytes[i - 2] != 'K') continue;
        i += 2;
        if (titleBytes[i - 2] != 'B') continue;

        if (('0' <= titleBytes[i] && titleBytes[i] <= '9')) {
            while ('0' <= titleBytes[i] && titleBytes[i] <= '9') {
                res *= 10;
                res += titleBytes[i] - '0';
                i += 2;
            }
            return res;
        }
    }
    return 0;
}

void kbs_InsertKB(TreeSet **root, TreeSet *node) {
    if (*root == NULL) {
        *root = node;
    } else {
        TreeSet *rootNode = *root;
        if (node->Value < rootNode->Value)
            kbs_InsertKB(&rootNode->Left, node);
        else if (node->Value > rootNode->Value)
            kbs_InsertKB(&rootNode->Right, node);
        else
            return;
    }
}

void kbs_appendKBs(clog_Arena *a, TreeSet *root) {
    LOG_DEBUG("\t\tkbs.c: Appending KB%d.", root->Value);
    if (root->Left) kbs_appendKBs(a, root->Left);
    clog_ArenaAppend(a, "\nKB%lu", root->Value);
    if (root->Right) kbs_appendKBs(a, root->Right);
}

void clog_kbs(clog_Arena scratch) {
    TreeSet *kbs = NULL;
    IUpdateSession *session = NULL;
    IUpdateSearcher *searcher = NULL;
    IUpdateHistoryEntryCollection *hist = NULL;
    clog_ArenaAppend(&scratch, "[kbs]");

    LOG_DEBUG("\tkbs.c: Initializing COM library.");
    HRESULT status = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (status != S_OK) {
        LOG_DEBUG("\tkbs.c: COM library could not be initalized, error code %lu.", GetLastError());
        clog_ArenaAppend(&scratch, "(Unable to initialize COM)");
        return;
    }

    LOG_DEBUG("\tkbs.c: Starting COM session.");
    status = CoCreateInstance(&CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, &IID_IUpdateSession, (LPVOID *)&session);
    if (status != S_OK) {
        LOG_DEBUG("\tkbs.c: Session startup failed, error code %lu.", GetLastError());
        goto Cleanup;
    }
    clog_Defer(&scratch, session, RETURN_LONG, session->lpVtbl->Release);

    LOG_DEBUG("\tkbs.c: Creating searcher.");
    status = session->lpVtbl->CreateUpdateSearcher(session, &searcher);
    if (status != S_OK) {
        LOG_DEBUG("\tkbs.c: Searcher creation failed, error code %lu.", GetLastError());
        goto Cleanup;
    }
    clog_Defer(&scratch, searcher, RETURN_LONG, searcher->lpVtbl->Release);

    LOG_DEBUG("\tkbs.c: Getting history count.");
    LONG count;
    status = searcher->lpVtbl->GetTotalHistoryCount(searcher, &count);
    if (status != S_OK) {
        LOG_DEBUG("\tkbs.c: Could not get history count, error code %lu.", GetLastError());
        goto Cleanup;
    }
    LOG_DEBUG("\tkbs.c: History count = %lu. Querying history.", count);
    searcher->lpVtbl->QueryHistory(searcher, 0, count, &hist);
    if (status != S_OK) {
        LOG_DEBUG("\tkbs.c: History query failed, error code %lu.", GetLastError());
        goto Cleanup;
    }
    clog_Defer(&scratch, hist, RETURN_LONG, hist->lpVtbl->Release);

    for (int i = 0; i < count; i++) {
        LOG_DEBUG("\tkbs.c: Item %d:", i);
        IUpdateHistoryEntry *item;
        hist->lpVtbl->get_Item(hist, i, &item);
        if (status != S_OK) {
            LOG_DEBUG("\t\tkbs.c: Could not get item %d, error code %lu.", i, GetLastError());
            continue;
        }

        wchar_t *title = NULL;
        item->lpVtbl->get_Title(item, (short unsigned int **)&title);
        if (status != S_OK) {
            LOG_DEBUG("\t\tkbs.c: Could not get item title, error code %lu.", GetLastError());
            goto NextItem;
        }

        LOG_DEBUG("\t\tkbs.c: Extracting KB number from title.");
        DWORD kb = kbs_ExtractKBNumber(title);
        if (kb) {
            LOG_DEBUG("\t\tkbs.c: Extracted KB%lu. Adding to list.", kb);
            TreeSet *node = clog_ArenaAlloc(&scratch, TreeSet, 1);
            *node = (TreeSet){0};
            node->Value = kb;
            kbs_InsertKB(&kbs, node);
        } else
            LOG_DEBUG("\t\tkbs.c: Title did not contain KB number, skipping.");

    NextItem:
        LOG_DEBUG("\t\tkbs.c: Releasing item %d.", i);
        item->lpVtbl->Release(item);
    }

Cleanup:
    LOG_DEBUG("\tkbs.c: Performing cleanup.");
    clog_PopDeferAll(&scratch);
    CoUninitialize();

    LOG_DEBUG("\tkbs.c: Cleanup complete.");
    if (kbs) {
        LOG_DEBUG("\tkbs.c: Printing KBs to output.");
        kbs_appendKBs(&scratch, kbs);
    } else {
        LOG_DEBUG("\tkbs.c: No installed KBs found.");
        clog_ArenaAppend(&scratch, "(No KBs found)");
    }
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_kbs(st->Memory);
    printf("%s", st->Start);
}
#endif