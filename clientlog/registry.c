
#include "arena.h"
#include "clientlog.h"

typedef struct {
    HKEY root;
    LPCSTR rootName;
    LPCSTR subkey;
    LPCSTR valueName;
} registry_Item;

static const registry_Item RegistryItems[] = {
    {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Axians\\ComputerProperties", "Customer"},
    {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Axians\\ComputerProperties", "CI"},
    {HKEY_LOCAL_MACHINE, "HKLM", "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Domain"},
};

#define REG_VALUE_BUF_SIZE 4096
#define REG_BINARY_PREVIEW_BYTES 32

static BOOL registry_TryReadAndAppendValue(const registry_Item *item, clog_Arena *scratch) {
    DWORD type = 0;
    DWORD cbData = 0;

    if (item == NULL || item->subkey == NULL || item->valueName == NULL) {
        return FALSE;
    }

    LONG status = RegGetValueA(item->root,
                               item->subkey,
                               item->valueName,
                               RRF_RT_ANY,
                               &type,
                               NULL,
                               &cbData);

    if (status != ERROR_SUCCESS || cbData == 0 || cbData > REG_VALUE_BUF_SIZE) {
        return FALSE;
    }

    BYTE valueBuf[REG_VALUE_BUF_SIZE];
    DWORD outSize = sizeof(valueBuf);
    CHAR prettyValue[REG_VALUE_BUF_SIZE + 64];
    prettyValue[0] = '\0';

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        status = RegGetValueA(item->root,
                              item->subkey,
                              item->valueName,
                              (type == REG_SZ) ? RRF_RT_REG_SZ : RRF_RT_REG_EXPAND_SZ,
                              NULL,
                              valueBuf,
                              &outSize);
        if (status != ERROR_SUCCESS || outSize == 0) {
            return FALSE;
        }

        valueBuf[sizeof(valueBuf) - 1] = '\0';
        snprintf(prettyValue, sizeof(prettyValue), "%s", (CHAR *)valueBuf);
        break;
    }
    case REG_MULTI_SZ: {
        status = RegGetValueA(item->root,
                              item->subkey,
                              item->valueName,
                              RRF_RT_REG_MULTI_SZ,
                              NULL,
                              valueBuf,
                              &outSize);
        if (status != ERROR_SUCCESS || outSize < 2) {
            return FALSE;
        }

        valueBuf[sizeof(valueBuf) - 1] = '\0';
        size_t written = 0;
        for (CHAR *p = (CHAR *)valueBuf; *p != '\0'; p += strlen(p) + 1) {
            int n = snprintf(&prettyValue[written], sizeof(prettyValue) - written, "%s%s", written == 0 ? "" : "; ", p);
            if (n <= 0 || (size_t)n >= sizeof(prettyValue) - written) {
                break;
            }
            written += (size_t)n;
        }

        if (written == 0) {
            return FALSE;
        }
        break;
    }
    case REG_DWORD: {
        DWORD value = 0;
        outSize = sizeof(value);
        status = RegGetValueA(item->root,
                              item->subkey,
                              item->valueName,
                              RRF_RT_REG_DWORD,
                              NULL,
                              &value,
                              &outSize);
        if (status != ERROR_SUCCESS || outSize != sizeof(value)) {
            return FALSE;
        }

        snprintf(prettyValue, sizeof(prettyValue), "%lu", value);
        break;
    }
    case REG_QWORD: {
        ULONGLONG value = 0;
        outSize = sizeof(value);
        status = RegGetValueA(item->root,
                              item->subkey,
                              item->valueName,
                              RRF_RT_REG_QWORD,
                              NULL,
                              &value,
                              &outSize);
        if (status != ERROR_SUCCESS || outSize != sizeof(value)) {
            return FALSE;
        }

        snprintf(prettyValue, sizeof(prettyValue), "%llu", value);
        break;
    }
    case REG_BINARY: {
        status = RegGetValueA(item->root,
                              item->subkey,
                              item->valueName,
                              RRF_RT_REG_BINARY,
                              NULL,
                              valueBuf,
                              &outSize);
        if (status != ERROR_SUCCESS || outSize == 0) {
            return FALSE;
        }

        size_t toPrint = min((size_t)outSize, (size_t)REG_BINARY_PREVIEW_BYTES);
        size_t written = 0;
        for (size_t i = 0; i < toPrint && written + 3 < sizeof(prettyValue); i++) {
            int n = snprintf(&prettyValue[written], sizeof(prettyValue) - written, "%02X", valueBuf[i]);
            if (n <= 0 || (size_t)n >= sizeof(prettyValue) - written) {
                break;
            }
            written += (size_t)n;
            if (i + 1 < toPrint && written + 2 < sizeof(prettyValue)) {
                prettyValue[written++] = ' ';
                prettyValue[written] = '\0';
            }
        }

        if (toPrint < outSize && written + 4 < sizeof(prettyValue)) {
            snprintf(&prettyValue[written], sizeof(prettyValue) - written, " ...");
        }
        break;
    }
    default:
        return FALSE;
    }

    if (prettyValue[0] == '\0') {
        return FALSE;
    }

    clog_ArenaAppend(scratch,
                     "\n%s\\%s\\%s:\t%s",
                     item->rootName,
                     item->subkey,
                     item->valueName,
                     prettyValue);
    return TRUE;
}

void clog_registry(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "[registry]");

    for (size_t i = 0; i < lengthof(RegistryItems); i++) {
        registry_TryReadAndAppendValue(&RegistryItems[i], &scratch);
    }

}


#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_registry(st->Memory);
    printf("%s", st->Start);
}
#endif
