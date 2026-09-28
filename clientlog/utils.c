#include "clientlog.h"
#include <errno.h>
#include <math.h>
#include <minwindef.h>
#include <string.h>

#define CLOG_CONFIG_MAX_LINE 1024

static VOID clog_utils_TrimConfigLine(CHAR *s) {
    size_t len;

    if (s == NULL)
        return;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        memmove(s, s + 1, strlen(s));
    }

    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                       s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[len - 1] = '\0';
        len--;
    }
}

static VOID clog_utils_StripConfigComment(CHAR *line) {
    CHAR *comment;

    if (line == NULL)
        return;

    comment = strchr(line, '#');
    if (comment != NULL) {
        *comment = '\0';
        clog_utils_TrimConfigLine(line);
    }
}

static BOOL clog_utils_IsConfigSection(const CHAR *line,
                                       const CHAR *sectionName) {
    CHAR expected[CLOG_CONFIG_MAX_LINE];
    CHAR clientlogExpected[CLOG_CONFIG_MAX_LINE];

    if (line == NULL || sectionName == NULL)
        return FALSE;

    snprintf(expected, sizeof(expected), "[%s]", sectionName);
    snprintf(clientlogExpected, sizeof(clientlogExpected), "[clientlog:%s]",
             sectionName);
    return _stricmp(line, expected) == 0 ||
           _stricmp(line, clientlogExpected) == 0;
}

/**
 * section name get prefixed with "clientlog:"
 *
 */
BOOL clog_utils_ReadConfigSection(const CHAR *path, const CHAR *sectionName,
                                  clog_utils_ConfigSectionLineFn onLine,
                                  void *ctx) {
    FILE *fp;
    DWORD lineNo = 0;
    BOOL inSection = FALSE;
    CHAR line[CLOG_CONFIG_MAX_LINE];

    if (path == NULL || sectionName == NULL || onLine == NULL)
        return FALSE;

    fp = fopen(path, "r");
    if (fp == NULL) {
        LOG_DEBUG("\tutils.c: Could not open config file '%s' (errno=%d: %s).",
                  path, errno, strerror(errno));
        return FALSE;
    }

    LOG_DEBUG("\tutils.c: Reading config section '%s' from '%s'.", sectionName,
              path);

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineNo++;
        clog_utils_TrimConfigLine(line);
        clog_utils_StripConfigComment(line);

        if (line[0] == '\0')
            continue;

        if (line[0] == '[') {
            inSection = clog_utils_IsConfigSection(line, sectionName);
            if (inSection) {
                LOG_DEBUG("\tutils.c: Found config section '%s' at %s:%lu.",
                          sectionName, path, lineNo);
            }
            continue;
        }

        if (line[0] == '.')
            continue;

        if (inSection && !onLine(path, lineNo, line, ctx))
            break;
    }

    fclose(fp);
    return TRUE;
}



/** Ensures that a string at most 'outSize' bytes worth of characters. Characters above
 * the limit (and 3 character before) are replaced with two period characters, i.e. "..".
 * If the input 'str' is an empty string, output buffer will contain a single dash, i.e. "-".
 * @param str string to
 * @param out a string buffer which will contain the pretty printed value.
 * @param outSize the number of bytes that can be written to out, must be at least 2
 * @return The input parameter "out" for convenience.
 */
LPSTR clog_utils_ClampString(LPSTR str, LPSTR out, size_t outSize) {
    int written = snprintf(out, outSize, "%s", str);
    if (written >= outSize && outSize > 7) {
        strcpy(&out[outSize - 3], "..");
    } else if (written == 0) {
        strcpy(out, "-");
    }

    return out;
}

/**
 * Pretty print a byte number to two decimal places.
 * @example clog_utils_PrettyBytes(2048, 0, ...) -> "2.00 KB"
 * @example clog_utils_PrettyBytes(8192, 2 ...) -> "0.01 MB" (rounded from 0,007813 MB)
 * @param bytes the byte number to pretty print.
 * @param target base 1024 magnitude to print, e.g. 1 MB = 1024^2 B, so for
 *               target = 2, bytes = 1 048 576 = 1.00 * 1024^2, we get "1.00 MB".
 *               A target of 0 (FALSE) means "try to find a best match".
 * @param out output buffer to store the result.
 * @return The input parameter "out" for convenience.
 */
LPSTR clog_utils_PrettyBytes(ULONGLONG bytes, DWORD target, LPSTR out) {
    static DOUBLE LOG1024E = 0.144269504088896340736;
    static LPCTSTR prefixes[] = {"", "K", "M", "G", "T"};

    // Given bytes = 1024^magnitude, then
    // magnitude = log_1024(bytes) = ln(bytes) * log_1024(e),
    DWORD magnitude = target ? target : (DWORD)(log(bytes) * LOG1024E);
    LPCTSTR prefix = prefixes[min(4, magnitude)];
    DOUBLE result = bytes * pow(1024.0, -(double)magnitude);
    snprintf(out, 16, "%.2lf %sB", result, prefix);
    return out;
}

/** Pretty print a SYSTEMTIME value.
 * @param t pointer to the SYSTEMTIME to pretty print.
 * @param flags must be one of clog_utils_TIMESTAMP_DATE, clog_utils_TIMESTAMP_CLOCK, clog_utils_TIMESTAMP_DATETIME, controls whether to print date (year-month-day) only, clock (hours:minutes:seconds) only, or both.
 * @param out a string buffer which will contain the pretty printed value.
 * @param outSize the number of bytes that can be written to out
 * @return The input parameter "out" for convenience.
 */
LPSTR clog_utils_PrettySystemtime(SYSTEMTIME *t, UINT8 flags, LPSTR out, size_t outSize) {
    DWORD written = 0;
    if (flags & clog_utils_TIMESTAMP_DATE) written += snprintf(&out[written], outSize - written, "%u-%02u-%02u", t->wYear, t->wMonth, t->wDay);
    if ((flags & clog_utils_TIMESTAMP_DATE) && (flags & clog_utils_TIMESTAMP_CLOCK)) written += snprintf(&out[written], outSize - written, " ");
    if (flags & clog_utils_TIMESTAMP_CLOCK) written += snprintf(&out[written], outSize - written, "%02u:%02u:%02u", t->wHour, t->wMinute, t->wSecond);
    return out;
}

#define PROCESS_TIMOUT_LIMIT_MS 1000
#define BUFREAD 513
void clog_utils_TrimTrailingNewlines(clog_Arena *scratch, BYTE *from) {
    clog_ArenaState *state = (clog_ArenaState *)scratch->State;
    if (!state || !state->Start || !state->End || !state->CurrentStart) {
        return;
    }

    if (!from || from < state->Start) {
        from = state->Start;
    }
    if (from > state->CurrentStart) {
        from = state->CurrentStart;
    }

    while (state->CurrentStart > from &&
           (state->CurrentStart[-1] == '\n' || state->CurrentStart[-1] == '\r')) {
        state->CurrentStart--;
    }

    if (state->CurrentStart < state->End) {
        *state->CurrentStart = '\0';
    }
}

/** Run a shell command and capture its output to a buffer. The buffer will be null-terminated.
 *
 *
 * @return ERROR_SUCCESS if the command finished successfully, otherwise an error code.
 */
DWORD clog_utils_RunCmdSynchronouslyToBuffer(CHAR *cmdline, CHAR *buffer, size_t bufferSize) {
    clog_ArenaState *scratchState = clog_ArenaMake(bufferSize);
    if (!scratchState || !scratchState->Start || !scratchState->End || !scratchState->CurrentStart) {
        return ERROR_INVALID_PARAMETER;
    }
    clog_Arena scratch = scratchState->Memory;

    DWORD status = clog_utils_RunCmdSynchronously(cmdline, scratch);

    strncpy(buffer, (char *)scratchState->Start, bufferSize - 1);
    buffer[bufferSize - 1] = '\0';

    return status;
}

/** Run a shell command. Callers should call clog_PopDeferAll(&scratch) after this function has been used.
 * @param cmdline the command to run, including flags
 * @param scratch a clientlog arena to which the output will be appended
 * @return If the command finished sucessfully, TRUE, otherwise FALSE. A command with an errored status code is not considered a failure.
 */
DWORD clog_utils_RunCmdSynchronously(CHAR *cmdline, clog_Arena scratch) {
    HANDLE hPipeOutputRead = NULL;
    HANDLE hPipeOutputWrite = NULL;
    DWORD status = 0;
    clog_ArenaState *scratchState = (clog_ArenaState *)scratch.State;
    if (!scratchState || !scratchState->Start || !scratchState->End || !scratchState->CurrentStart) {
        return ERROR_INVALID_PARAMETER;
    }
    BYTE *outputStart = scratchState->CurrentStart;

    SECURITY_ATTRIBUTES securityAttributes;
    // Set the bInheritHandle flag so pipe handles are inherited.
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&hPipeOutputRead, &hPipeOutputWrite, &securityAttributes, 0)) {
        status = GetLastError();
        clog_ArenaAppend(&scratch, "(Failed to run command, unknown error. Error code 1.%#010x.)", status);
        return status;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(hPipeOutputRead, HANDLE_FLAG_INHERIT, 0)) {
        status = GetLastError();
        clog_ArenaAppend(&scratch, "(Failed to run command, unknown error. Error code 2.%#010x.)", status);
        CloseHandle(hPipeOutputRead);
        CloseHandle(hPipeOutputWrite);
        return status;
    }

    PROCESS_INFORMATION procInfo;
    ZeroMemory(&procInfo, sizeof(procInfo));
    STARTUPINFO startInfo;
    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(STARTUPINFO);
    startInfo.hStdError = hPipeOutputWrite;
    startInfo.hStdOutput = hPipeOutputWrite;
    startInfo.dwFlags |= STARTF_USESTDHANDLES;

    // CreateProcess may modify lpCommandLine in-place; copy to a writable buffer.
    CHAR cmdlineBuf[4096];
    strncpy(cmdlineBuf, cmdline, sizeof(cmdlineBuf) - 1);
    cmdlineBuf[sizeof(cmdlineBuf) - 1] = '\0';

    status = CreateProcess(NULL,
                           cmdlineBuf,
                           NULL,
                           NULL,
                           TRUE, // important, must inherit handles due to STARTF_USESTDHANDLES
                           0,
                           NULL,
                           NULL,
                           &startInfo,
                           &procInfo);

    CloseHandle(hPipeOutputWrite);
    if (!status) {
        status = GetLastError();
        clog_ArenaAppend(&scratch, "(Failed to run command, could not create process from '%s'. Error code 3.%#010x.)", cmdline, status);
        CloseHandle(hPipeOutputRead);
        return status;
    }

    // Poll: drain the pipe continuously while waiting for the process to exit.
    // A blocking WaitForSingleObject before ReadFile deadlocks when the child's
    // output fills the pipe buffer (child blocks on WriteFile, parent blocks on Wait).
    DWORD readBufLen = 0;
    CHAR readBuf[BUFREAD];
    DWORD startTick = GetTickCount();
    BOOL processExited = FALSE;

    while (!processExited) {
        // Drain all currently available pipe data to keep the child unblocked.
        DWORD available = 0;
        while (PeekNamedPipe(hPipeOutputRead, NULL, 0, NULL, &available, NULL) && available > 0) {
            DWORD toRead = min(available, (DWORD)(BUFREAD - 1));
            if (!ReadFile(hPipeOutputRead, readBuf, toRead, &readBufLen, NULL) || readBufLen == 0) break;
            readBuf[readBufLen] = '\0';
            clog_ArenaAppend(&scratch, "%s", readBuf);
        }

        status = WaitForSingleObject(procInfo.hProcess, 0);
        if (status == WAIT_OBJECT_0) {
            processExited = TRUE;
        } else if (status == WAIT_FAILED) {
            status = GetLastError();
            clog_ArenaAppend(&scratch, "(Failed to run command, unknown error. Error code 4.%#010x.)", status);
            TerminateProcess(procInfo.hProcess, 1);
            CloseHandle(procInfo.hProcess);
            CloseHandle(procInfo.hThread);
            CloseHandle(hPipeOutputRead);
            return status;
        } else if (GetTickCount() - startTick >= PROCESS_TIMOUT_LIMIT_MS) {
            clog_ArenaAppend(&scratch, "(Failed to run command, process took more than %dms to run. Error code 5.%lu.)", PROCESS_TIMOUT_LIMIT_MS, (DWORD)WAIT_TIMEOUT);
            TerminateProcess(procInfo.hProcess, 1);
            CloseHandle(procInfo.hProcess);
            CloseHandle(procInfo.hThread);
            CloseHandle(hPipeOutputRead);
            return WAIT_TIMEOUT;
        } else {
            Sleep(20);
        }
    }

    // Drain remaining output non-blocking; a descended process may still hold the write
    // end open after the original exits, so a blocking ReadFile could wait indefinitely.
    DWORD available = 0;
    while (PeekNamedPipe(hPipeOutputRead, NULL, 0, NULL, &available, NULL) && available > 0) {
        DWORD toRead = min(available, (DWORD)(BUFREAD - 1));
        if (!ReadFile(hPipeOutputRead, readBuf, toRead, &readBufLen, NULL) || readBufLen == 0) break;
        readBuf[readBufLen] = '\0';
        clog_ArenaAppend(&scratch, "%s", readBuf);
    }

    CloseHandle(procInfo.hProcess);
    CloseHandle(procInfo.hThread);
    CloseHandle(hPipeOutputRead);

    // Most commands print one trailing CRLF; trim it to avoid blank lines in reports.
    clog_utils_TrimTrailingNewlines(&scratch, outputStart);

    if (scratchState->CurrentStart <= outputStart) {
        clog_ArenaAppend(&scratch, "(No output)");
    }

    return status;
}
#undef BUFREAD
#undef PROCESS_TIMOUT_LIMIT_MS
