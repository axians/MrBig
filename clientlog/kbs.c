#include "clientlog.h"
#include <initguid.h>
#include <wbemidl.h>
#include <wuerror.h>

#ifdef STANDALONE
// This is to be able to compile kbs.exe as a standalone exe to test
// Otherwise, LOG_DEBUG is an alias to mrlog, which is not available in a standalone exe
#undef LOG_DEBUG

#define LOG_DEBUG(fmt, ...)                                                                        \
    do {                                                                                           \
        printf("\t" fmt "\n", ##__VA_ARGS__);                                                      \
    } while (0)

#endif

typedef struct TreeSet {
    struct TreeSet *Left;
    struct TreeSet *Right;
    DWORD Value;
} TreeSet;

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
    if (root->Left)
        kbs_appendKBs(a, root->Left);
    clog_ArenaAppend(a, "\nKB%lu", root->Value);
    if (root->Right)
        kbs_appendKBs(a, root->Right);
}

void clog_kbs(clog_Arena scratch) {
    TreeSet *kbs = NULL;

    IWbemLocator *locator = NULL;
    IWbemServices *services = NULL;
    IEnumWbemClassObject *enumerator = NULL;
    clog_ArenaAppend(&scratch, "[kbs]");



    LOG_DEBUG("\tkbs.c: Initializing COM library.");
    HRESULT status = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(status)) {
        LOG_DEBUG("\tkbs.c: COM library could not be initalized, error code %lu.", GetLastError());
        clog_ArenaAppend(&scratch, "(Unable to initialize COM)");
        return;
    }

#define HANDLE_COM_ALLOCATION(obj)                                                               \
    if (FAILED(status)) {                                                                   \
        LOG_DEBUG("\tkbs.c: COM library " #obj " failed, error code %lu.", GetLastError()); \
        goto Cleanup;                                                                       \
    }                                                                                       \
    clog_Defer(&scratch, obj, RETURN_LONG, obj->lpVtbl->Release)

    LOG_DEBUG("\tkbs.c: Starting COM session.");
    status = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator,
                          (LPVOID *)&locator);

    HANDLE_COM_ALLOCATION(locator);

    LOG_DEBUG("\tkbs.c: Connecting to WMI service.");
    status = locator->lpVtbl->ConnectServer(locator, L"ROOT\\CIMV2", NULL, NULL, 0, 0, 0, 0, &services);
    HANDLE_COM_ALLOCATION(services);

    LOG_DEBUG("\tkbs.c: Creating CoSetProxyBlanket.");
    status = CoSetProxyBlanket((IUnknown *)services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    HANDLE_COM_ALLOCATION(services);

    LOG_DEBUG("\tkbs.c: Executing WMI query to get list of installed KBs.");
    status = services->lpVtbl->ExecQuery(services, L"WQL",
                                     L"SELECT HotFixID FROM Win32_QuickFixEngineering",
                                     WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator);
    HANDLE_COM_ALLOCATION(enumerator);

    while (1) {
        IWbemClassObject *obj = NULL;
        ULONG returned = 0;

        status = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &obj, &returned);

        if (returned == 0 || FAILED(status)) {
            // No more results or an error occurred, either way break out of the loop
            break;
        }

        VARIANT value;
        VariantInit(&value);

        status = obj->lpVtbl->Get(obj, L"HotFixID", 0, &value, NULL, NULL);

        if (SUCCEEDED(status) && value.vt == VT_BSTR && value.bstrVal) {

            DWORD kb = kbs_ExtractKBNumber(value.bstrVal);
            LOG_DEBUG("\t\tkbs.c: Extracted KB number %lu from WMI query result.", kb);
            if (kb > 0) {
                TreeSet *node = clog_ArenaAlloc(&scratch, TreeSet, 1);
                *node = (TreeSet){0};
                node->Value = kb;
                kbs_InsertKB(&kbs, node);
            }
        }

        LOG_DEBUG("\tkbs.c: Releasing WMI object.");
        VariantClear(&value);
        obj->lpVtbl->Release(obj);
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
