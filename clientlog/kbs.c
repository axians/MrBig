#include <windows.h>
#include <initguid.h>
#include <wuapi.h>
#include <wuapi.h>
#include <wuerror.h>
#include <stdio.h>
#include "arena.h"

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
    if (root->Left) kbs_appendKBs(a, root->Left);
    clog_ArenaAppend(a, "\nKB%lu", root->Value);
    if (root->Right) kbs_appendKBs(a, root->Right);
}

void clog_kbs(clog_Arena scratch) {
    TreeSet *kbs = NULL;
    IUpdateSession *session = NULL;
    IUpdateSearcher *searcher = NULL;
    IUpdateHistoryEntryCollection *hist = NULL;

    HRESULT status = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (status != S_OK) {
        goto Cleanup;
    }

    status = CoCreateInstance(&CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, &IID_IUpdateSession, (LPVOID *)&session);
    clog_Defer(&scratch, session, RETURN_LONG, session->lpVtbl->Release);
    if (status != S_OK) {
        goto Cleanup;
    }

    status = session->lpVtbl->CreateUpdateSearcher(session, &searcher);
    clog_Defer(&scratch, searcher, RETURN_LONG, searcher->lpVtbl->Release);
    if (status != S_OK) {
        goto Cleanup;
    }

    LONG count;
    status = searcher->lpVtbl->GetTotalHistoryCount(searcher, &count);
    if (status != S_OK) {
        goto Cleanup;
    }
    searcher->lpVtbl->QueryHistory(searcher, 0, count, &hist);
    clog_Defer(&scratch, hist, RETURN_LONG, hist->lpVtbl->Release);
    if (status != S_OK) {
        goto Cleanup;
    }


    for (int i = 0; i < count; i++) {
        IUpdateHistoryEntry *item;
        hist->lpVtbl->get_Item(hist, i, &item);
        if (status != S_OK) {
            continue;
        }

        wchar_t *title = NULL;
        item->lpVtbl->get_Title(item, (short unsigned int **)&title);

        if (status != S_OK) {
            continue;
        }
        
        DWORD kb = kbs_ExtractKBNumber(title);
        if (kb) {
            TreeSet *node = clog_ArenaAlloc(&scratch, TreeSet, 1);
            *node = (TreeSet){0};
            node->Value = kb;
            kbs_InsertKB(&kbs, node);
        }

        item->lpVtbl->Release(item);
    }

Cleanup:
    clog_PopDeferAll(&scratch);
    CoUninitialize();

    clog_ArenaAppend(&scratch, "[kbs]");
    if (kbs)
    kbs_appendKBs(&scratch, kbs);
    else
        clog_ArenaAppend(&scratch, "(No KBs found)");
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_kbs(st->Memory);
    printf("%s", st->Start);
}
#endif