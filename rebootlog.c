#include "mrbig.h"

#define EVENTLOG_STOPPED_EVENT_ID 6006
#define SYSTEM_RESTART_INITATED_EVENT_ID 1074
#define MAX_RECORD_SIZE 0x10000           // 64KiB
#define MAX_EVENT_AGE (60 * 60 * 24 * 30) // in seconds
#define MAX_EVENT_TIMEGAP (60 * 15)       // in seconds

BOOL LoadEvents(HANDLE hEventLog, EVENTLOGRECORD **lpBuffer, DWORD *pnBytesRead) {
    DWORD status, nNumberOfBytesToRead = MAX_RECORD_SIZE, pnMinNumberOfBytesNeeded;
    EVENTLOGRECORD *reallocLogRecord;

    *lpBuffer = big_malloc("lpBuffer (LoadEvents)", MAX_RECORD_SIZE);

    while (!ReadEventLog(hEventLog,
                         EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ,
                         0,
                         *lpBuffer,
                         nNumberOfBytesToRead,
                         pnBytesRead,
                         &pnMinNumberOfBytesNeeded)) {
        status = GetLastError();
        if (status == ERROR_INSUFFICIENT_BUFFER) { // Should only happen if ReadEventLog changes behavior in the future
            status = ERROR_SUCCESS;
            reallocLogRecord = (EVENTLOGRECORD *)big_realloc("lpBuffer (LoadEvents)", *lpBuffer, pnMinNumberOfBytesNeeded);
            *lpBuffer = reallocLogRecord;
            nNumberOfBytesToRead = pnMinNumberOfBytesNeeded;
        } else {
            if (ERROR_HANDLE_EOF != status) {
                if (debug) mrlog("LoadEvents (rebootlog): ReadEventLog failed with %lu.", status);
            }
            return FALSE;
        }
    }

    return TRUE;
}

restart_event *recent_restarts(WORD maxNumRestarts) {
    HANDLE systemLog = OpenEventLog(NULL, "System");
    EVENTLOGRECORD *logEventRecords, *currEventRecord;
    DWORD readBytes;
    LONGLONG fileTimeGeneratedSeconds;
    FILETIME fileTimeGenerated;
    SYSTEMTIME systemTimeGenerated;
    time_t currentTime = time(NULL);

    restart_event *restart, *firstRestart = NULL, *restartPrev = NULL;
    WORD numRestartsFound = 0;
    DWORD restartTime;

    EVENTLOGRECORD *currEventLogStoppedEvent = NULL; // Event ID 6006

    while (LoadEvents(systemLog, &logEventRecords, &readBytes)) {
        currEventRecord = logEventRecords;
        while (readBytes > 0 && numRestartsFound < maxNumRestarts && (currentTime - currEventRecord->TimeGenerated) < MAX_EVENT_AGE) {
            INT16 eventID = currEventRecord->EventID & 0xFFFF;
            if (eventID == EVENTLOG_STOPPED_EVENT_ID) {
                currEventLogStoppedEvent = currEventRecord;
            } else if (eventID == SYSTEM_RESTART_INITATED_EVENT_ID) {
                if (currEventLogStoppedEvent != NULL &&
                    currEventLogStoppedEvent->TimeGenerated - currEventRecord->TimeGenerated > MAX_EVENT_TIMEGAP) {
                    restartTime = currEventRecord->TimeGenerated;
                } else {
                    restartTime = currEventLogStoppedEvent->TimeGenerated;
                }

                // Unixtime to Systemtime
                fileTimeGeneratedSeconds = Int32x32To64(restartTime, 10000000) + 116444736000000000;
                fileTimeGenerated.dwLowDateTime = (DWORD)fileTimeGeneratedSeconds;
                fileTimeGenerated.dwHighDateTime = fileTimeGeneratedSeconds >> 32;
                FileTimeToSystemTime(&fileTimeGenerated, &systemTimeGenerated);

                restart = big_malloc("restart event (recent_restarts)", sizeof(*restart));
                restart->wYear = systemTimeGenerated.wYear;
                restart->wMonth = systemTimeGenerated.wMonth;
                restart->wDay = systemTimeGenerated.wDay;
                restart->wHour = systemTimeGenerated.wHour;
                restart->wMinute = systemTimeGenerated.wMinute;
                restart->wSecond = systemTimeGenerated.wSecond;

                char *params[currEventRecord->NumStrings];
                char *param = ((char *)currEventRecord + currEventRecord->StringOffset);
                for (int i = 0; i < currEventRecord->NumStrings; i++) {
                    params[i] = param;
                    param += strlen(param) + 1;
                }
                if (currEventRecord->NumStrings > 2) {
                    strncpy(restart->sReason, params[2], sizeof(restart->sReason));
                    restart->sReason[sizeof(restart->sReason) - 1] = '\0';
                } else {
                    strcpy(restart->sReason, "unknown");
                }
                if (currEventRecord->NumStrings > 6) {
                    strncpy(restart->sUser, params[6], sizeof(restart->sUser));
                    restart->sUser[sizeof(restart->sUser) - 1] = '\0';
                } else {
                    strcpy(restart->sUser, "unknown");
                }

                restart->next = NULL;

                if (restartPrev) {
                    restartPrev->next = restart;
                } else {
                    firstRestart = restart;
                }
                restartPrev = restart;
                numRestartsFound++;
            }
            readBytes -= currEventRecord->Length;
            currEventRecord = (EVENTLOGRECORD *)((LPBYTE)currEventRecord + currEventRecord->Length);
        }
    }

    if (logEventRecords) big_free("logEventRecords (recent_restarts)", logEventRecords);
    if (systemLog) CloseEventLog(systemLog);

    return firstRestart;
}