#include "clientlog.h"
#include <initguid.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <winerror.h>
#include <winscard.h>
#include <wuerror.h>

#ifdef STANDALONE
// This is to be able to compile kbs.exe as a standalone exe to test
// Otherwise, LOG_DEBUG is an alias to mrlog, which is not available in a
// standalone exe
#undef LOG_DEBUG

#define LOG_DEBUG(fmt, ...)                                                    \
    do {                                                                       \
        printf(fmt "\n", ##__VA_ARGS__);                                  \
    } while (0)

#endif


typedef struct TreeSet {
    struct TreeSet *Left;
    struct TreeSet *Right;
    DWORD Value;
    char dateInstalled[11]; // Format: YYYY-MM-DD
} TreeSet;

static int kbs_isFallbackDate(const char *dateStr) {
    return strcmp(dateStr, "1970-01-01") == 0;
}

static int kbs_shouldReplaceDate(const char *existingDate,
                                 const char *incomingDate) {
    if (kbs_isFallbackDate(incomingDate))
        return 0;
    if (kbs_isFallbackDate(existingDate))
        return 1;
    return 0;
}

DWORD kbs_ExtractKBNumber(wchar_t *title) {
    DWORD res = 0;
    BYTE *titleBytes = (BYTE *)title;
    int i = 0;
    while (titleBytes[i] != '\0') {
        i += 2;
        if (titleBytes[i - 2] != 'K')
            continue;
        i += 2;
        if (titleBytes[i - 2] != 'B')
            continue;

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

void kbs_UpsertKB(TreeSet **root, clog_Arena *scratch, DWORD kb,
                  const char *dateInstalled) {
    if (*root == NULL) {
        TreeSet *node = clog_ArenaAlloc(scratch, TreeSet, 1);
        *node = (TreeSet){0};
        node->Value = kb;
        memcpy(node->dateInstalled, dateInstalled, 11);
        *root = node;
        return;
    }

    TreeSet *rootNode = *root;
    if (kb < rootNode->Value) {
        kbs_UpsertKB(&rootNode->Left, scratch, kb, dateInstalled);
        return;
    }
    if (kb > rootNode->Value) {
        kbs_UpsertKB(&rootNode->Right, scratch, kb, dateInstalled);
        return;
    }

    if (kbs_shouldReplaceDate(rootNode->dateInstalled, dateInstalled))
        memcpy(rootNode->dateInstalled, dateInstalled, 11);
}

static size_t kbs_count(TreeSet *root) {
    if (root == NULL)
        return 0;
    return 1 + kbs_count(root->Left) + kbs_count(root->Right);
}

static void kbs_collect(TreeSet *root, TreeSet **items, size_t *index) {
    if (root == NULL)
        return;
    items[*index] = root;
    (*index)++;
    kbs_collect(root->Left, items, index);
    kbs_collect(root->Right, items, index);
}

static int kbs_compareByDateThenKB(const void *lhs, const void *rhs) {
    const TreeSet *left = *(const TreeSet *const *)lhs;
    const TreeSet *right = *(const TreeSet *const *)rhs;

    int dateCmp = strcmp(left->dateInstalled, right->dateInstalled);
    if (dateCmp != 0)
        return dateCmp;

    return (left->Value < right->Value)
               ? -1
               : (left->Value > right->Value) ? 1 : 0;
}

static void kbs_appendKBsSorted(clog_Arena *a, TreeSet *root) {
    size_t kbCount = kbs_count(root);
    if (kbCount == 0)
        return;

    TreeSet **items = clog_ArenaAlloc(a, TreeSet *, kbCount);
    size_t index = 0;
    kbs_collect(root, items, &index);
    qsort(items, kbCount, sizeof(TreeSet *), kbs_compareByDateThenKB);

    for (size_t i = 0; i < kbCount; i++) {
        LOG_DEBUG("\t\tkbs.c: Appending KB%lu %s.", items[i]->Value,
                  items[i]->dateInstalled);
        clog_ArenaAppend(a, "\nKB%lu %s", items[i]->Value,
                         items[i]->dateInstalled);
    }
}

int kbs_getDateElementOrder() {
    wchar_t formatBuffer[10] = {0};
    
    // Retrieve the short date format ordering identifier
    // 0 = Month-Day-Year (e.g., US)
    // 1 = Day-Month-Year (e.g., Europe)
    // 2 = Year-Month-Day (e.g., ISO / East Asia)
    if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_IDATE, formatBuffer, 10) > 0) {
        return _wtoi(formatBuffer);
    }
    return -1; // Unknown
}

void kbs_customParse(char* dest, BSTR localizedDateStr) {
    // Fallback default value if parsing fails completely
    snprintf(dest, 11, "1970-01-01");

    if (localizedDateStr == NULL || wcslen(localizedDateStr) == 0) {
        return;
    }

    int order = kbs_getDateElementOrder();
    int v1 = 0, v2 = 0, v3 = 0;
    
    // L"%d%*[^0-9]%d%*[^0-9]%d" extracts 3 numbers and safely throws away 
    // any separators (slashes, dots, dashes, or spaces) automatically.
    int parsedItems = swscanf(localizedDateStr, L"%d%*[^0-9]%d%*[^0-9]%d", &v1, &v2, &v3);
    
    // We must successfully extract exactly 3 distinct numeric segments
    if (parsedItems != 3) {
        return; 
    }

    int year = 0, month = 0, day = 0;

    switch(order) {
        case 0: // MM/DD/YYYY
            month = v1; day = v2; year = v3;
            break;
        case 1: // DD/MM/YYYY
            day = v1; month = v2; year = v3;
            break;
        case 2: // YYYY/MM/DD
            year = v1; month = v2; day = v3;
            break;
        default:
            return; // Unknown system locale format layout
    }

    // this means that the month and day are switched
    if (month > 12 && day <= 12)
    {
        int temp = month;
        month = day;
        day = temp;
    }
    // Quick structural sanity check to protect against corrupted string data
    if (month < 1 || month > 12 || day < 1 || day > 31 || year < 1971 || year > 9999) {
        return;
    }
    

    // Safely write the standardized, region-neutral string to your 11-byte char buffer
    // Output format: YYYY-MM-DD (e.g., "2026-06-30")
    snprintf(dest, 11, "%04d-%02d-%02d", year, month, day);
}

static void kbs_scanRegistryUninstall(clog_Arena *scratch, TreeSet **kbs, const wchar_t *path, REGSAM samDesired) {
    HKEY hUninstall;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        path,
        0, KEY_READ | samDesired, &hUninstall);

    if (result != ERROR_SUCCESS) {
        LOG_DEBUG("\tkbs.c: Could not open Uninstall registry key '%ls' (sam=0x%lx), error %ld.",
                  path, (unsigned long)samDesired, (long)result);
        return;
    }

    WCHAR subkeyName[256];
    DWORD index = 0;

    while (1) {
        DWORD subkeyNameLen = 256;
        result = RegEnumKeyExW(hUninstall, index++, subkeyName, &subkeyNameLen,
                               NULL, NULL, NULL, NULL);
        if (result == ERROR_NO_MORE_ITEMS)
            break;
        if (result != ERROR_SUCCESS)
            continue;

        HKEY hEntry;
        if (RegOpenKeyExW(hUninstall, subkeyName, 0, KEY_READ | samDesired,
                          &hEntry) != ERROR_SUCCESS)
            continue;

        // Try subkey name first for KB number, then fall back to DisplayName
        DWORD kb = kbs_ExtractKBNumber(subkeyName);
        if (kb == 0) {
            WCHAR displayName[512] = {0};
            DWORD displayNameLen = sizeof(displayName) - sizeof(WCHAR); // reserve room for null
            DWORD displayNameType = 0;
            if (RegQueryValueExW(hEntry, L"DisplayName", NULL, &displayNameType,
                                 (LPBYTE)displayName, &displayNameLen) == ERROR_SUCCESS &&
                (displayNameType == REG_SZ || displayNameType == REG_EXPAND_SZ)) {
                // Guarantee null termination in case the stored value lacks it
                displayName[sizeof(displayName) / sizeof(WCHAR) - 1] = L'\0';
                kb = kbs_ExtractKBNumber(displayName);
            }
        }

        if (kb > 0) {
            char dateStr[11];
            snprintf(dateStr, 11, "1970-01-01");

            WCHAR installDate[16] = {0};
            DWORD installDateLen = sizeof(installDate) - sizeof(WCHAR); // reserve room for null
            DWORD installDateType = 0;
            if (RegQueryValueExW(hEntry, L"InstallDate", NULL, &installDateType,
                                 (LPBYTE)installDate, &installDateLen) == ERROR_SUCCESS &&
                (installDateType == REG_SZ || installDateType == REG_EXPAND_SZ)) {
                // Guarantee null termination in case the stored value lacks it
                installDate[sizeof(installDate) / sizeof(WCHAR) - 1] = L'\0';
                // InstallDate is stored as YYYYMMDD
                int year = 0, month = 0, day = 0;
                if (swscanf(installDate, L"%4d%2d%2d", &year, &month, &day) == 3 &&
                    month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
                    year >= 1971 && year <= 9999) {
                    snprintf(dateStr, 11, "%04d-%02d-%02d", year, month, day);
                }
            }

            LOG_DEBUG("\t\tkbs.c: Registry found KB%lu installed %s.", kb, dateStr);
            kbs_UpsertKB(kbs, scratch, kb, dateStr);
        }

        RegCloseKey(hEntry);
    }

    RegCloseKey(hUninstall);
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
        LOG_DEBUG(
            "\tkbs.c: COM library could not be initalized, error code %lu.",
            GetLastError());
        clog_ArenaAppend(&scratch, "(Unable to initialize COM)");
        return;
    }

#define HANDLE_COM_ALLOCATION(obj)                                             \
    if (FAILED(status)) {                                                      \
        LOG_DEBUG("\tkbs.c: COM library " #obj " failed, error code %lu.",     \
                  GetLastError());                                             \
        goto Cleanup;                                                          \
    }                                                                          \
    clog_Defer(&scratch, obj, RETURN_LONG, obj->lpVtbl->Release)

    LOG_DEBUG("\tkbs.c: Starting COM session.");
    status = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                              &IID_IWbemLocator, (LPVOID *)&locator);

    HANDLE_COM_ALLOCATION(locator);

    LOG_DEBUG("\tkbs.c: Connecting to WMI service.");
    status = locator->lpVtbl->ConnectServer(locator, L"ROOT\\CIMV2", NULL, NULL,
                                            0, 0, 0, 0, &services);
    HANDLE_COM_ALLOCATION(services);

    LOG_DEBUG("\tkbs.c: Creating CoSetProxyBlanket.");
    status = CoSetProxyBlanket((IUnknown *)services, RPC_C_AUTHN_WINNT,
                               RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                               RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    HANDLE_COM_ALLOCATION(services);

    LOG_DEBUG("\tkbs.c: Executing WMI query to get list of installed KBs.");
    status = services->lpVtbl->ExecQuery(
        services, L"WQL",
        L"SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering",
        WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator);
    HANDLE_COM_ALLOCATION(enumerator);

    while (1) {
        IWbemClassObject *obj = NULL;
        ULONG returned = 0;

        status = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &obj,
                                          &returned);

        if (returned == 0 || FAILED(status)) {
            // No more results or an error occurred, either way break out of the
            // loop
            break;
        }

        VARIANT value;
        VariantInit(&value);
        VARIANT dateInstalled;
        VariantInit(&dateInstalled);

        status = obj->lpVtbl->Get(obj, L"HotFixID", 0, &value, NULL, NULL);
        HRESULT dateStatus = obj->lpVtbl->Get(obj, L"InstalledOn", 0,
                                              &dateInstalled, NULL, NULL);
        if ((FAILED(status) || value.vt != VT_BSTR || !value.bstrVal) ||
            (FAILED(dateStatus) || dateInstalled.vt != VT_BSTR ||
             !dateInstalled.bstrVal)) {
            LOG_DEBUG("\t\tkbs.c: Could not get HotFixID.");
            VariantClear(&value);
            obj->lpVtbl->Release(obj);
            LOG_DEBUG("\t\tkbs.c: Releasing early WMI object.");
            continue;
        }
        // success

        DWORD kb = kbs_ExtractKBNumber(value.bstrVal);
        LOG_DEBUG("\t\tkbs.c: Extracted KB number %lu from WMI query result.",
                  kb);
        if (kb > 0) {
            char dateStr[11];
            kbs_customParse(dateStr, dateInstalled.bstrVal);
            kbs_UpsertKB(&kbs, &scratch, kb, dateStr);
        }


        LOG_DEBUG("\t\tkbs.c: Releasing WMI object.");
        VariantClear(&value);
        VariantClear(&dateInstalled);
        obj->lpVtbl->Release(obj);
    }

Cleanup:
    LOG_DEBUG("\tkbs.c: Performing cleanup.");
    clog_PopDeferAll(&scratch);
    CoUninitialize();

    LOG_DEBUG("\tkbs.c: Cleanup complete.");

    LOG_DEBUG("\tkbs.c: Scanning registry Uninstall key for KBs (64-bit view).");
    kbs_scanRegistryUninstall(&scratch, &kbs,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        KEY_WOW64_64KEY);
    LOG_DEBUG("\tkbs.c: Scanning registry Uninstall key for KBs (32-bit view).");
    kbs_scanRegistryUninstall(&scratch, &kbs,
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        KEY_WOW64_64KEY);

    if (kbs) {
        LOG_DEBUG("\tkbs.c: Printing KBs to output.");
        kbs_appendKBsSorted(&scratch, kbs);
    } else {
        LOG_DEBUG("\tkbs.c: No installed KBs found.");
        clog_ArenaAppend(&scratch, "(No KBs found)");
    }
    clog_utils_TrimTrailingNewlines(&scratch, NULL);
    clog_ArenaAppend(&scratch, "\n");

}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_kbs(st->Memory);
    printf("%s", st->Start);
}
#endif
