#include "arena.h"
#include "clientlog.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winevt.h>

#define MAX_PROVIDER_NAME_LENGTH (255)
#define MAX_EVENT_MESSAGE_SIZE (0x1000) // 4 KB
#define MAX_EVENTLOG_ROW_SIZE (512)
#define EVENTLOG_CONFIG_MAX_LINE (1024)

// Due to string literal concatenation in EvtQuery below, you must treat this as a string (not a number) when modifying
// For example, a writing 3600 * 1000 instead of 3600000 will not work
#define MAX_EVENT_AGE_MS 3600000

typedef struct {
    LPCWSTR ChannelName;
    LPCSTR ConfigName;
} eventlog_Channel;

static eventlog_Channel CHANNELS[] = {
    {L"Application", "application"},
    {L"Setup", "setup"},
    {L"System", "system"},
};
static size_t NUM_CHANNELS = sizeof(CHANNELS) / sizeof(*CHANNELS);

typedef struct {
    BOOL *channelEnabled;
} eventlog_ConfigContext;

typedef struct {
    ULONGLONG Timestamp;
    CHAR Provider[MAX_PROVIDER_NAME_LENGTH];
    CHAR Message[MAX_EVENT_MESSAGE_SIZE];
    UINT16 EventID;
    UINT8 Level;
} eventlog_Event;

static BOOL eventlog_BuildCfgCachePath(const CHAR *systemRoot,
                                       const CHAR *systemDir, CHAR *path,
                                       size_t pathSize) {
    size_t rootLen;
    int ret;

    if (systemRoot == NULL || systemRoot[0] == '\0' || systemDir == NULL ||
        path == NULL || pathSize == 0) {
        return FALSE;
    }

    rootLen = strlen(systemRoot);
    if (rootLen > 0 && (systemRoot[rootLen - 1] == '\\' ||
                        systemRoot[rootLen - 1] == '/')) {
        ret = snprintf(path, pathSize, "%s%s\\cfg.cache", systemRoot,
                       systemDir);
    } else {
        ret = snprintf(path, pathSize, "%s\\%s\\cfg.cache", systemRoot,
                       systemDir);
    }

    return ret >= 0 && (size_t)ret < pathSize;
}

static BOOL eventlog_BuildLocalConfigPath(CHAR *path, size_t pathSize) {
    DWORD pathLen;
    CHAR *separator;
    CHAR *forwardSeparator;
    size_t directoryLen;

    if (path == NULL || pathSize == 0 || pathSize > MAXDWORD)
        return FALSE;

    pathLen = GetModuleFileNameA(NULL, path, (DWORD)pathSize);
    if (pathLen == 0 || pathLen >= pathSize)
        return FALSE;

    separator = strrchr(path, '\\');
    forwardSeparator = strrchr(path, '/');
    if (forwardSeparator != NULL &&
        (separator == NULL || forwardSeparator > separator)) {
        separator = forwardSeparator;
    }
    if (separator == NULL)
        return FALSE;

    directoryLen = (size_t)(separator - path) + 1;
    if (directoryLen + sizeof("mrbig.cfg") > pathSize)
        return FALSE;

    strcpy(path + directoryLen, "mrbig.cfg");
    return TRUE;
}

static BOOL eventlog_DisableChannel(LPCSTR channelName,
                                    BOOL *channelEnabled) {
    if (channelName == NULL || channelEnabled == NULL)
        return FALSE;

    for (size_t i = 0; i < NUM_CHANNELS; i++) {
        if (_stricmp(channelName, CHANNELS[i].ConfigName) == 0) {
            channelEnabled[i] = FALSE;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL eventlog_LoadConfigLine(const CHAR *path, DWORD lineNo,
                                    const CHAR *line, void *ctx) {
    CHAR command[32];
    CHAR channelName[32];
    CHAR extra[2];
    eventlog_ConfigContext *config = (eventlog_ConfigContext *)ctx;
    int fields;

    if (line == NULL || config == NULL || config->channelEnabled == NULL)
        return FALSE;

    fields = sscanf(line, "%31s %31s %1s", command, channelName, extra);
    if (fields == 2 && _stricmp(command, "disable") == 0 &&
        eventlog_DisableChannel(channelName, config->channelEnabled)) {
        LOG_DEBUG("\teventlog.c: Disabled event log channel '%s' from %s:%lu.",
                  channelName, path, lineNo);
    } else {
        LOG_DEBUG("\teventlog.c: Ignoring eventlog config at %s:%lu -> '%s'.",
                  path, lineNo, line);
    }

    return TRUE;
}

static VOID eventlog_LoadConfig(BOOL *channelEnabled) {
    const CHAR *systemRoot = getenv("SystemRoot");
    CHAR cfgCachePath[EVENTLOG_CONFIG_MAX_LINE];
    CHAR localConfigPath[EVENTLOG_CONFIG_MAX_LINE];
    eventlog_ConfigContext config;
    BOOL cfgCacheRead = FALSE;

    if (channelEnabled == NULL)
        return;

    config.channelEnabled = channelEnabled;
    if (eventlog_BuildCfgCachePath(systemRoot, "System32", cfgCachePath,
                                   sizeof(cfgCachePath)) &&
        clog_utils_ReadConfigSection(cfgCachePath, "eventlog",
                                     eventlog_LoadConfigLine, &config)) {
        cfgCacheRead = TRUE;
    }

    if (!cfgCacheRead &&
        eventlog_BuildCfgCachePath(systemRoot, "Sysnative", cfgCachePath,
                                   sizeof(cfgCachePath))) {
        clog_utils_ReadConfigSection(cfgCachePath, "eventlog",
                                     eventlog_LoadConfigLine, &config);
    }

    if (eventlog_BuildLocalConfigPath(localConfigPath,
                                      sizeof(localConfigPath))) {
        clog_utils_ReadConfigSection(localConfigPath, "eventlog",
                                     eventlog_LoadConfigLine, &config);
    }
}

LPCSTR eventlog_PrettyEventLevel(UINT8 level) {
    switch (level) {
    case 0:
        return "Always";
    case 1:
        return "Critical";
    case 2:
        return "Error";
    case 3:
        return "Warning";
    case 4:
        return "Info";
    case 5:
        return "Verbose";
    default:
        return "Unknown";
    }
}

LPSTR eventlog_PrettyEvent(eventlog_Event *e, CHAR *out) {
    CHAR eventTimestamp[24], providerBuffer[30], eventMessageClamped[440];
    SYSTEMTIME t;
    FileTimeToSystemTime((FILETIME *)&e->Timestamp, &t);

    snprintf(out, MAX_EVENTLOG_ROW_SIZE, "%-23s\t%6d \t%-7s\t %-30s\t%s",
             clog_utils_PrettySystemtime(&t, clog_utils_TIMESTAMP_DATETIME, eventTimestamp, sizeof(eventTimestamp)),
             e->EventID,
             eventlog_PrettyEventLevel(e->Level),
             clog_utils_ClampString(e->Provider, providerBuffer, sizeof(providerBuffer)),
             clog_utils_ClampString(e->Message, eventMessageClamped, sizeof(eventMessageClamped)));
    return out;
}

eventlog_Event eventlog_GetEventData(EVT_HANDLE eventHandle) {
    eventlog_Event result = {0};

    // Follows general steps of .Net (C#) class EventLogRecord.cs, from System.Diagnostics.Reader
    EVT_HANDLE contextHandle = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);

    DWORD bufferNeeded, propCount;
    BOOL status = EvtRender(contextHandle, eventHandle, EvtRenderEventValues, 0, NULL, &bufferNeeded, &propCount);
    DWORD error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER) {
        EvtClose(contextHandle);
        return result;
    }

    EVT_VARIANT eventSystemProperties[bufferNeeded / sizeof(EVT_VARIANT)];
    status = EvtRender(contextHandle, eventHandle, EvtRenderEventValues, bufferNeeded, eventSystemProperties, &bufferNeeded, &propCount);
    if (!status) {
        EvtClose(contextHandle);
        return result;
    }

    EVT_VARIANT timestampPending = eventSystemProperties[EvtSystemTimeCreated];
    if (timestampPending.Type != EvtVarTypeNull) {
        result.Timestamp = timestampPending.FileTimeVal;
    }

    EVT_VARIANT providerNamePending = eventSystemProperties[EvtSystemProviderName];
    LPCWSTR providerName = NULL;
    if (providerNamePending.Type != EvtVarTypeNull) {
        providerName = providerNamePending.StringVal;
        size_t providerNameWritten = wcstombs(result.Provider, providerName, MAX_PROVIDER_NAME_LENGTH);
        if (providerNameWritten >= MAX_PROVIDER_NAME_LENGTH) result.Provider[MAX_PROVIDER_NAME_LENGTH - 1] = '\0';
    }

    EVT_VARIANT eventIdPending = eventSystemProperties[EvtSystemEventID];
    if (eventIdPending.Type != EvtVarTypeNull) {
        result.EventID = eventIdPending.UInt16Val;
    }

    EVT_VARIANT levelPending = eventSystemProperties[EvtSystemLevel];
    if (levelPending.Type != EvtVarTypeNull) {
        result.Level = levelPending.ByteVal;
    }

    if (providerName != NULL) {
        // TODO: cache publisher handles like in .NET EventLogRecord.
        EVT_HANDLE pmHandle = EvtOpenPublisherMetadata(NULL, providerName, NULL, 0, 0); // RE providerName. We cannot use result.Provider, since we need wchar_t*

        WCHAR emptyBuffer[1] = {L'\0'}; // Due to: https://github.com/dotnet/runtime/issues/100198"
        status = EvtFormatMessage(pmHandle, eventHandle, 0, 0, NULL, EvtFormatMessageEvent, 0, emptyBuffer, &bufferNeeded);
        error = GetLastError();
        if (!status && // EventLogRecord says: Unresolved inserts are indications that strings COULD be missing, and are not real errors
            error != ERROR_EVT_UNRESOLVED_VALUE_INSERT &&
            error != ERROR_EVT_UNRESOLVED_PARAMETER_INSERT &&
            error != ERROR_INSUFFICIENT_BUFFER) {
            EvtClose(pmHandle);
            EvtClose(contextHandle);
            return result;
        }

        WCHAR messageBuffer[bufferNeeded];
        status = EvtFormatMessage(pmHandle, eventHandle, 0, 0, NULL, EvtFormatMessageEvent, bufferNeeded, messageBuffer, &bufferNeeded);
        error = GetLastError();
        EvtClose(pmHandle);
        if (!status &&
            error != ERROR_EVT_UNRESOLVED_VALUE_INSERT &&
            error != ERROR_EVT_UNRESOLVED_PARAMETER_INSERT) {
            EvtClose(contextHandle);
            return result;
        }
        size_t messageWritten = wcstombs(result.Message, messageBuffer, MAX_EVENT_MESSAGE_SIZE);
        if (messageWritten >= MAX_EVENT_MESSAGE_SIZE) result.Message[MAX_EVENT_MESSAGE_SIZE - 1] = '\0';
    }

    EvtClose(contextHandle);
    return result;
}

void clog_eventlog(DWORD maxNumEvents, clog_Arena scratch) {
    CHAR eventBuffer[MAX_EVENTLOG_ROW_SIZE];
    BOOL channelEnabled[sizeof(CHANNELS) / sizeof(*CHANNELS)];

    for (DWORD channelIx = 0; channelIx < NUM_CHANNELS; channelIx++) {
        channelEnabled[channelIx] = TRUE;
    }
    eventlog_LoadConfig(channelEnabled);

    for (DWORD channelIx = 0; channelIx < NUM_CHANNELS; channelIx++) {
        CHAR channelName[32];
        wcstombs(channelName, CHANNELS[channelIx].ChannelName, 32);
        if (!channelEnabled[channelIx]) {
            clog_ArenaAppend(&scratch, "[eventlog_%s]", CharLowerA(channelName));
            clog_ArenaAppend(&scratch, "\n(Channel monitoring was disabled by config.)");
            clog_ArenaAppend(&scratch, "\n");
            clog_ArenaAppend(&scratch, "\n");
            continue;
        }

        clog_ArenaAppend(&scratch, "[eventlog_%s]", CharLowerA(channelName));

        EVT_HANDLE hLog = EvtQuery(NULL, CHANNELS[channelIx].ChannelName, L"Event/System[Level<4 and TimeCreated[timediff(@SystemTime) <= " STR(MAX_EVENT_AGE_MS) "]]", EvtQueryChannelPath | EvtQueryReverseDirection);
        clog_Defer(&scratch, hLog, RETURN_INT, &EvtClose);

        EVT_HANDLE event[maxNumEvents];
        DWORD nEvents = 0;
        EvtNext(hLog, maxNumEvents, event, INFINITE, 0, &nEvents);
        if (nEvents > 0) {
            clog_ArenaAppend(&scratch, "\n%-23s\t%6s \t%-7s\t %-30s\t%s", "Timestamp", "Id", "Level", "Source", "Message");

            for (DWORD i = 0; i < nEvents; i++) {
                eventlog_Event e = eventlog_GetEventData(event[i]);
                clog_Defer(&scratch, event[i], RETURN_INT, &EvtClose);
                clog_ArenaAppend(&scratch, "\n%s", eventlog_PrettyEvent(&e, eventBuffer));
                clog_PopDefer(&scratch);
            }
        } else {
            clog_ArenaAppend(&scratch, "\n(No warnings or errors found within the last %dh.)", MAX_EVENT_AGE_MS / 3600000);
        }
        clog_ArenaAppend(&scratch, "\n");
        clog_ArenaAppend(&scratch, "\n");
        clog_PopDefer(&scratch);
    }
    clog_utils_TrimTrailingNewlines(&scratch, NULL);
    clog_ArenaAppend(&scratch, "\n");
}

#ifdef STANDALONE
int main(int argc, char *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x100000);
    clog_eventlog(5, st->Memory);
    clog_PopDeferAll(&st->Memory);
    printf((char *)st->Start);
    return 0;
}
#endif
