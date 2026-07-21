
#include "arena.h"
#include "clientlog.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef STANDALONE
// This is to be able to compile registry.exe as a standalone exe to test.
// Otherwise, LOG_DEBUG is an alias to mrlog, which is not available in a
// standalone exe.
#undef LOG_DEBUG

#define LOG_DEBUG(fmt, ...)                                                    \
    do {                                                                       \
        printf(fmt "\n", ##__VA_ARGS__);                                      \
    } while (0)

#endif

typedef struct {
    HKEY root;
    LPCSTR rootName;
    LPCSTR subkey;
    LPCSTR valueName;
} registry_Item;

static const registry_Item RegistryDefaultItems[] = {
    {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Axians\\ComputerProperties", "Customer"},
    {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Axians\\ComputerProperties", "CI"},
    {HKEY_LOCAL_MACHINE, "HKLM", "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Domain"},
};

#define REG_VALUE_BUF_SIZE 4096
#define REG_BINARY_PREVIEW_BYTES 32
#define REGISTRY_MAX_CONFIG_ITEMS 64
#define REGISTRY_MAX_LINE 1024
#define REGISTRY_MAX_SUBKEY 768
#define REGISTRY_MAX_VALUE 256

typedef struct {
    registry_Item Item;
    CHAR Subkey[REGISTRY_MAX_SUBKEY];
    CHAR ValueName[REGISTRY_MAX_VALUE];
} registry_ConfigItem;

static BOOL registry_ItemsEqual(const registry_Item *a, const registry_Item *b) {
    if (a == NULL || b == NULL) return FALSE;
    if (a->root != b->root) return FALSE;
    if (a->subkey == NULL || b->subkey == NULL || a->valueName == NULL || b->valueName == NULL) return FALSE;
    return _stricmp(a->subkey, b->subkey) == 0 && _stricmp(a->valueName, b->valueName) == 0;
}

static BOOL registry_ContainsItem(const registry_ConfigItem *items, size_t numItems, const registry_Item *candidate) {
    if (items == NULL || candidate == NULL) return FALSE;
    for (size_t i = 0; i < numItems; i++) {
        if (registry_ItemsEqual(&items[i].Item, candidate)) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID registry_AddDefaultItems(registry_ConfigItem *items, size_t *numItems) {
    if (items == NULL || numItems == NULL) return;

    for (size_t i = 0; i < lengthof(RegistryDefaultItems); i++) {
        if (*numItems >= REGISTRY_MAX_CONFIG_ITEMS) {
            LOG_DEBUG("\tregistry.c: Reached max config items while adding defaults.");
            return;
        }

        if (registry_ContainsItem(items, *numItems, &RegistryDefaultItems[i])) {
            continue;
        }

        registry_ConfigItem *dst = &items[*numItems];
        dst->Item.root = RegistryDefaultItems[i].root;
        dst->Item.rootName = RegistryDefaultItems[i].rootName;
        snprintf(dst->Subkey, sizeof(dst->Subkey), "%s", RegistryDefaultItems[i].subkey);
        snprintf(dst->ValueName, sizeof(dst->ValueName), "%s", RegistryDefaultItems[i].valueName);
        dst->Item.subkey = dst->Subkey;
        dst->Item.valueName = dst->ValueName;
        (*numItems)++;
    }
}

static VOID registry_Trim(CHAR *s) {
    size_t len;

    if (s == NULL) return;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        memmove(s, s + 1, strlen(s));
    }

    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[len - 1] = '\0';
        len--;
    }
}

static VOID registry_SanitizeConfigEntry(CHAR *line) {
    CHAR *comment = NULL;

    if (line == NULL) return;

    // Allow inline comments in config lines, e.g. "...\\ValueName # note".
    comment = strstr(line, " #");
    if (comment == NULL) comment = strstr(line, " ;");
    if (comment != NULL) {
        *comment = '\0';
    }

    registry_Trim(line);

    // Strip optional wrapping quotes.
    size_t n = strlen(line);
    if (n >= 2 && ((line[0] == '"' && line[n - 1] == '"') || (line[0] == '\'' && line[n - 1] == '\''))) {
        memmove(line, line + 1, n - 2);
        line[n - 2] = '\0';
        registry_Trim(line);
    }
}

static BOOL registry_ParseRoot(LPCSTR root, HKEY *hRoot, LPCSTR *rootName) {
    if (root == NULL || hRoot == NULL || rootName == NULL) return FALSE;

    if (_stricmp(root, "HKLM") == 0 || _stricmp(root, "HKEY_LOCAL_MACHINE") == 0) {
        *hRoot = HKEY_LOCAL_MACHINE;
        *rootName = "HKLM";
        return TRUE;
    }
    if (_stricmp(root, "HKCU") == 0 || _stricmp(root, "HKEY_CURRENT_USER") == 0) {
        *hRoot = HKEY_CURRENT_USER;
        *rootName = "HKCU";
        return TRUE;
    }
    if (_stricmp(root, "HKCR") == 0 || _stricmp(root, "HKEY_CLASSES_ROOT") == 0) {
        *hRoot = HKEY_CLASSES_ROOT;
        *rootName = "HKCR";
        return TRUE;
    }
    if (_stricmp(root, "HKU") == 0 || _stricmp(root, "HKEY_USERS") == 0) {
        *hRoot = HKEY_USERS;
        *rootName = "HKU";
        return TRUE;
    }
    if (_stricmp(root, "HKCC") == 0 || _stricmp(root, "HKEY_CURRENT_CONFIG") == 0) {
        *hRoot = HKEY_CURRENT_CONFIG;
        *rootName = "HKCC";
        return TRUE;
    }

    return FALSE;
}

static BOOL registry_AddItemFromPath(const CHAR *line, registry_ConfigItem *items, size_t *numItems) {
    CHAR normalized[REGISTRY_MAX_LINE];
    CHAR *firstSlash;
    CHAR *lastSlash;
    CHAR rootToken[64];
    size_t rootLen;
    HKEY root = NULL;
    LPCSTR rootName = NULL;
    registry_ConfigItem *dst;

    if (line == NULL || items == NULL || numItems == NULL) return FALSE;
    if (*numItems >= REGISTRY_MAX_CONFIG_ITEMS) return FALSE;

    snprintf(normalized, sizeof(normalized), "%s", line);
    registry_SanitizeConfigEntry(normalized);
    if (normalized[0] == '\0') {
        return FALSE;
    }

    for (size_t i = 0; normalized[i] != '\0'; i++) {
        if (normalized[i] == '/') normalized[i] = '\\';
    }

    firstSlash = strchr(normalized, '\\');
    lastSlash = strrchr(normalized, '\\');
    if (firstSlash == NULL || lastSlash == NULL || firstSlash == lastSlash) {
        return FALSE;
    }

    rootLen = (size_t)(firstSlash - normalized);
    if (rootLen == 0 || rootLen >= sizeof(rootToken)) {
        return FALSE;
    }
    memcpy(rootToken, normalized, rootLen);
    rootToken[rootLen] = '\0';

    *firstSlash = '\0';
    if (!registry_ParseRoot(rootToken, &root, &rootName)) {
        return FALSE;
    }
    *firstSlash = '\\';

    *lastSlash = '\0';
    dst = &items[*numItems];
    dst->Item.root = root;
    dst->Item.rootName = rootName;
    snprintf(dst->Subkey, sizeof(dst->Subkey), "%s", firstSlash + 1);
    snprintf(dst->ValueName, sizeof(dst->ValueName), "%s", lastSlash + 1);
    if (dst->Subkey[0] == '\0' || dst->ValueName[0] == '\0') {
        return FALSE;
    }
    dst->Item.subkey = dst->Subkey;
    dst->Item.valueName = dst->ValueName;

    if (registry_ContainsItem(items, *numItems, &dst->Item)) {
        return FALSE;
    }

    (*numItems)++;

    return TRUE;
}

static VOID registry_LoadConfigFile(const CHAR *path, registry_ConfigItem *items, size_t *numItems) {
    FILE *fp;
    CHAR line[REGISTRY_MAX_LINE];
    CHAR parseLine[REGISTRY_MAX_LINE];
    DWORD lineNo = 0;
    BOOL inRegistrySection = FALSE;
    size_t beforeCount;

    if (path == NULL || items == NULL || numItems == NULL) return;
    if (*numItems >= REGISTRY_MAX_CONFIG_ITEMS) return;

    beforeCount = *numItems;
    fp = fopen(path, "r");
    if (fp == NULL) {
        LOG_DEBUG("\tregistry.c: Could not open config file '%s' (errno=%d: %s).",
                  path,
                  errno,
                  strerror(errno));
        return;
    }

    LOG_DEBUG("\tregistry.c: Reading config from '%s'.", path);

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineNo++;
        registry_Trim(line);

        if (line[0] == '\0' || line[0] == '#') continue;

        if (line[0] == '[') {
            inRegistrySection = (_stricmp(line, "[clientlog:registry]") == 0 || _stricmp(line, "[registry]") == 0);
            if (inRegistrySection) {
                LOG_DEBUG("\tregistry.c: Found registry section at %s:%lu.", path, lineNo);
            }
            continue;
        }

        // Ignore directives such as .include/.config for this module.
        if (line[0] == '.') continue;

        if (inRegistrySection) {
            snprintf(parseLine, sizeof(parseLine), "%s", line);
            if (!registry_AddItemFromPath(parseLine, items, numItems)) {
                LOG_DEBUG("\tregistry.c: Ignoring registry entry at %s:%lu (invalid or duplicate) -> '%s'.", path, lineNo, line);
            }
            if (*numItems >= REGISTRY_MAX_CONFIG_ITEMS) break;
        }
    }

    fclose(fp);
    LOG_DEBUG("\tregistry.c: Loaded %llu registry item(s) from '%s'.",
              (unsigned long long)(*numItems - beforeCount),
              path);
}

static VOID registry_GetConfiguredItems(registry_ConfigItem *items, size_t *numItems, CHAR *sourceOut, size_t sourceOutSize) {
    const CHAR *systemRoot = getenv("SystemRoot");
    CHAR system32CfgCachePath[REGISTRY_MAX_LINE];
    CHAR sysnativeCfgCachePath[REGISTRY_MAX_LINE];

    if (items == NULL || numItems == NULL) {
        if (sourceOut != NULL && sourceOutSize > 0) {
            snprintf(sourceOut, sourceOutSize, "%s", "defaults");
        }
        return;
    }

    if (sourceOut != NULL && sourceOutSize > 0) {
        sourceOut[0] = '\0';
    }

    *numItems = 0;
    registry_AddDefaultItems(items, numItems);

    if (systemRoot != NULL && systemRoot[0] != '\0') {
        CHAR sep = '\\';
        size_t rootLen = strlen(systemRoot);
        if (rootLen > 0 && (systemRoot[rootLen - 1] == '\\' || systemRoot[rootLen - 1] == '/')) {
            sep = '\0';
        }

        if (sep == '\\') {
            snprintf(system32CfgCachePath, sizeof(system32CfgCachePath), "%s\\System32\\cfg.cache", systemRoot);
        } else {
            snprintf(system32CfgCachePath, sizeof(system32CfgCachePath), "%sSystem32\\cfg.cache", systemRoot);
        }

        size_t beforeConfigCount = *numItems;
        registry_LoadConfigFile(system32CfgCachePath, items, numItems);
        if (*numItems > beforeConfigCount && sourceOut != NULL && sourceOutSize > 0) {
            snprintf(sourceOut, sourceOutSize, "%s", system32CfgCachePath);
        }

        // On 32-bit processes running on 64-bit Windows, System32 can be redirected.
        // Try Sysnative as a fallback view of real System32.
        if (*numItems == 0) {
            if (sep == '\\') {
                snprintf(sysnativeCfgCachePath, sizeof(sysnativeCfgCachePath), "%s\\Sysnative\\cfg.cache", systemRoot);
            } else {
                snprintf(sysnativeCfgCachePath, sizeof(sysnativeCfgCachePath), "%sSysnative\\cfg.cache", systemRoot);
            }

            size_t beforeConfigCount = *numItems;
            registry_LoadConfigFile(sysnativeCfgCachePath, items, numItems);
            if (*numItems > beforeConfigCount && sourceOut != NULL && sourceOutSize > 0) {
                snprintf(sourceOut, sourceOutSize, "%s", sysnativeCfgCachePath);
            }
        }
    }

    {
        size_t beforeConfigCount = *numItems;
        registry_LoadConfigFile("mrbig.cfg", items, numItems);
        if (*numItems > beforeConfigCount && sourceOut != NULL && sourceOutSize > 0) {
            snprintf(sourceOut, sourceOutSize, "%s", "mrbig.cfg");
        }
    }

    if (sourceOut != NULL && sourceOutSize > 0 && sourceOut[0] == '\0') {
        snprintf(sourceOut, sourceOutSize, "%s", "defaults");
    }

    LOG_DEBUG("\tregistry.c: Using %llu registry item(s) (defaults included), config source '%s'.",
              (unsigned long long)*numItems,
              sourceOut && sourceOut[0] ? sourceOut : "unknown");

    return;
}

static BOOL registry_TryReadAndAppendValue(const registry_Item *item, clog_Arena *scratch) {
    DWORD type = 0;
    DWORD cbData = 0;

    if (item == NULL || item->subkey == NULL || item->valueName == NULL || scratch == NULL || scratch->State == NULL) {
        LOG_DEBUG("\t\tregistry.c: Invalid input to registry_TryReadAndAppendValue.");
        return FALSE;
    }

    LOG_DEBUG("\t\tregistry.c: Reading %s\\%s\\%s.", item->rootName, item->subkey, item->valueName);

    LONG status = RegGetValueA(item->root,
                               item->subkey,
                               item->valueName,
                               RRF_RT_ANY,
                               &type,
                               NULL,
                               &cbData);

    if (status != ERROR_SUCCESS || cbData == 0 || cbData > REG_VALUE_BUF_SIZE) {
        LOG_DEBUG("\t\tregistry.c: Value missing or unsupported for %s\\%s\\%s (status=%ld, size=%lu).",
                  item->rootName,
                  item->subkey,
                  item->valueName,
                  status,
                  cbData);
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
            LOG_DEBUG("\t\tregistry.c: Failed reading string value for %s\\%s\\%s (status=%ld, size=%lu).",
                      item->rootName,
                      item->subkey,
                      item->valueName,
                      status,
                      outSize);
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
            LOG_DEBUG("\t\tregistry.c: Failed reading multi-string value for %s\\%s\\%s (status=%ld, size=%lu).",
                      item->rootName,
                      item->subkey,
                      item->valueName,
                      status,
                      outSize);
            return FALSE;
        }

        valueBuf[sizeof(valueBuf) - 2] = '\0';
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
            LOG_DEBUG("\t\tregistry.c: Failed reading DWORD value for %s\\%s\\%s (status=%ld, size=%lu).",
                      item->rootName,
                      item->subkey,
                      item->valueName,
                      status,
                      outSize);
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
            LOG_DEBUG("\t\tregistry.c: Failed reading QWORD value for %s\\%s\\%s (status=%ld, size=%lu).",
                      item->rootName,
                      item->subkey,
                      item->valueName,
                      status,
                      outSize);
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
            LOG_DEBUG("\t\tregistry.c: Failed reading binary value for %s\\%s\\%s (status=%ld, size=%lu).",
                      item->rootName,
                      item->subkey,
                      item->valueName,
                      status,
                      outSize);
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
        LOG_DEBUG("\t\tregistry.c: Unsupported registry type %lu for %s\\%s\\%s.",
                  type,
                  item->rootName,
                  item->subkey,
                  item->valueName);
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
    LOG_DEBUG("\t\tregistry.c: Read succeeded for %s\\%s\\%s.", item->rootName, item->subkey, item->valueName);
    return TRUE;
}

void clog_registry(clog_Arena scratch) {
    registry_ConfigItem configuredItems[REGISTRY_MAX_CONFIG_ITEMS];
    size_t numItems = 0;
    size_t numAttempted = 0;
    size_t numSucceeded = 0;
    CHAR configSource[REGISTRY_MAX_LINE];
    registry_GetConfiguredItems(configuredItems, &numItems, configSource, sizeof(configSource));

    LOG_DEBUG("\tregistry.c: Config source '%s'.", configSource[0] ? configSource : "unknown");
    LOG_DEBUG("\tregistry.c: Starting registry read pass with %llu item(s).", (unsigned long long)numItems);

    if (scratch.State == NULL) {
        LOG_DEBUG("\tregistry.c: Arena state is NULL, aborting registry output to avoid crash.");
        return;
    }

    clog_ArenaAppend(&scratch, "[registry]");

    LOG_DEBUG("\tregistry.c: Parsed registry config items:");
    for (size_t i = 0; i < numItems; i++) {
        LOG_DEBUG("\t\t[%llu] Root='%s' Path='%s' Subvalue='%s'",
                  (unsigned long long)(i + 1),
                  configuredItems[i].Item.rootName ? configuredItems[i].Item.rootName : "(null)",
                  configuredItems[i].Item.subkey ? configuredItems[i].Item.subkey : "(null)",
                  configuredItems[i].Item.valueName ? configuredItems[i].Item.valueName : "(null)");
    }
    LOG_DEBUG("\tregistry.c: Finished listing parsed items, starting lookups.");

    for (size_t i = 0; i < numItems; i++) {
        numAttempted++;
        if (registry_TryReadAndAppendValue(&configuredItems[i].Item, &scratch)) {
            numSucceeded++;
        }
    }

    LOG_DEBUG("\tregistry.c: Completed registry read pass (attempted=%llu, succeeded=%llu, skipped=%llu).",
              (unsigned long long)numAttempted,
              (unsigned long long)numSucceeded,
              (unsigned long long)(numAttempted - numSucceeded));

}


#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_registry(st->Memory);
    printf("%s", st->Start);
}
#endif
