#include "clientlog.h"
#include <time.h>
#include <windows.h>

#define TIME_BUF_SIZE 64
#define REG_VAL_SIZE  256

static void clock_PrettyIso8601LocalTime(const SYSTEMTIME *t, CHAR *out, size_t outSize) {
    if (outSize == 0) return;

    TIME_ZONE_INFORMATION tzi;
    DWORD tzStatus = GetTimeZoneInformation(&tzi);
    LONG biasMinutes = tzi.Bias;

    if (tzStatus == TIME_ZONE_ID_STANDARD) {
        biasMinutes += tzi.StandardBias;
    } else if (tzStatus == TIME_ZONE_ID_DAYLIGHT) {
        biasMinutes += tzi.DaylightBias;
    }

    LONG offsetMinutes = -biasMinutes;
    char sign = '+';
    if (offsetMinutes < 0) {
        sign = '-';
        offsetMinutes = -offsetMinutes;
    }

    snprintf(out,
             outSize,
             "%04u-%02u-%02uT%02u:%02u:%02u%c%02ld:%02ld",
             t->wYear,
             t->wMonth,
             t->wDay,
             t->wHour,
             t->wMinute,
             t->wSecond,
             sign,
             offsetMinutes / 60,
             offsetMinutes % 60);
}

void clog_clock(clog_Arena scratch) {
    time_t unixtime = time(NULL);
    struct tm *tm_time; // careful, pointers returned by localtime and gmtime point to the same memory

    SYSTEMTIME t;
    GetLocalTime(&t);

    tm_time = localtime(&unixtime);
    CHAR localBuf[TIME_BUF_SIZE];
    /* strftime(localBuf, TIME_BUF_SIZE, "%a %d %b %H:%M:%S %Y", tm_time); */
    strftime(localBuf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", tm_time);

    GetSystemTime(&t);
    CHAR localISOBuf[TIME_BUF_SIZE];
    clock_PrettyIso8601LocalTime(&t, localISOBuf, TIME_BUF_SIZE);

    tm_time = gmtime(&unixtime);
    CHAR utcBuf[TIME_BUF_SIZE];
    strftime(utcBuf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", tm_time);

    /* Read NTP type and server from the W32Time registry key */
    CHAR ntpType[REG_VAL_SIZE]   = "-";
    CHAR ntpServer[REG_VAL_SIZE] = "-";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD cbData = REG_VAL_SIZE;
        RegQueryValueExA(hKey, "Type",      NULL, NULL, (LPBYTE)ntpType,   &cbData);
        cbData = REG_VAL_SIZE;
        RegQueryValueExA(hKey, "NtpServer", NULL, NULL, (LPBYTE)ntpServer, &cbData);
        RegCloseKey(hKey);
    }

    clog_ArenaAppend(&scratch, "[clock]");
    clog_ArenaAppend(&scratch, "\nepoch: %lld", (long long)unixtime);
    clog_ArenaAppend(&scratch, "\nlocal: %s", localBuf);
    clog_ArenaAppend(&scratch, "\nISO: %s", localISOBuf);
    clog_ArenaAppend(&scratch, "\nUTC: %s", utcBuf);
    clog_ArenaAppend(&scratch, "\nTime Synchronisation type: %s", ntpType);
    clog_ArenaAppend(&scratch, "\nNTP server: %s\n", ntpServer);

    /* Only query w32tm if the W32Time service is actually running.
       On non-domain-joined machines the service is often stopped,
       which causes w32tm to print an unhelpful COM error. */
    BOOL w32timeRunning = FALSE;
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, "W32Time", SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS ss;
            if (QueryServiceStatus(hSvc, &ss))
                w32timeRunning = (ss.dwCurrentState == SERVICE_RUNNING);
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    if (w32timeRunning) {
        clog_utils_RunCmdSynchronously("C:\\Windows\\System32\\w32tm.exe /query /status", scratch);
    } else {
        clog_ArenaAppend(&scratch, "W32Time service is not running.\n");
    }
}

#ifdef STANDALONE
int main(int argc, char *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_clock(st->Memory);
    printf("%s", st->Start);
    return 0;
}
#endif
