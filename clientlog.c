#include "mrbig.h"

#define MINUTE (60 * 1000)
#define HOUR (60 * MINUTE)
#define DAY (24 * HOUR)
#define TIME_BUF_SIZE 12
#define OUTPUTS_BUF_SIZE 255
#define REBOOTLOG_BUF_SIZE 600

enum Reportables { // TODO: Allow selection of what to report through config
    REPORT_DATE,
    REPORT_OSVERSION,
    REPORT_UPTIME
};
typedef enum Reportables Reportable;

VOID date(LPTSTR out) {
    WCHAR w_date[TIME_BUF_SIZE];
    CHAR s_date[TIME_BUF_SIZE];
    GetDateFormatEx(L"sv-SE", DATE_SHORTDATE, NULL, NULL, w_date, TIME_BUF_SIZE, NULL);
    wcstombs(s_date, w_date, TIME_BUF_SIZE);

    WCHAR w_time[TIME_BUF_SIZE];
    CHAR s_time[TIME_BUF_SIZE];
    GetTimeFormatEx(L"sv-SE", TIME_FORCE24HOURFORMAT, NULL, NULL, w_time, TIME_BUF_SIZE);
    wcstombs(s_time, w_time, TIME_BUF_SIZE);

    snprintf(out, OUTPUTS_BUF_SIZE, "%s %s", s_date, s_time);
}

LPCTSTR osversion() {
    OSVERSIONINFOEX version;
    ZeroMemory(&version, sizeof(OSVERSIONINFOEX));
    version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFOA)&version);
    // see https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
    LPTSTR osName = "(unknown)";

    DWORD maj = version.dwMajorVersion;
    DWORD min = version.dwMinorVersion;
    BYTE type = version.wProductType;
    /* NB. Windows 8.1 / 10 and later do not support GetVersion or GetVersionEx, and will return Windows 8 instead
    if (maj == 10 && min == 0) {
        if (type == VER_NT_WORKSTATION)
            osName = "Windows 10";
        else
            osName = "Windows Server 2016";

    } else if (maj == 6 && min == 3) {
        if (type == VER_NT_WORKSTATION)
            osName = "Windows 8.1";
        else
            osName = "Windows Server 2012 R2";

    } else*/ if (maj == 6 && min == 2) {
        if (type == VER_NT_WORKSTATION)
            osName = "Windows 8 or later";
        else
            osName = "Windows Server 2012 or later";

    } else if (maj == 6 && min == 1) {
        if (type == VER_NT_WORKSTATION)
            osName = "Windows 7";
        else
            osName = "Windows Server 2008 R2";

    } else if (maj == 6 && min == 0) {
        if (type == VER_NT_WORKSTATION)
            osName = "Windows Vista";
        else
            osName = "Windows Server 2008";
    } else if (maj == 5 && min == 2) {
        if (GetSystemMetrics(SM_SERVERR2) != 0)
            osName = "Windows Server 2003 R2";
        else if (version.wSuiteMask & VER_SUITE_WH_SERVER)
            osName = "Windows Home Server";
        else if (GetSystemMetrics(SM_SERVERR2) == 0)
            osName = "Windows Server 2003";
    }

    return osName;
}

VOID uptime(LPTSTR out) {
    SYSTEMTIME systime;
    SYSTEMTIME boottime;
    FILETIME systime_filetime;
    FILETIME boottime_filetime;
    ULARGE_INTEGER systime_lu;
    ULARGE_INTEGER boottime_lu;

    GetSystemTime(&systime);
    SystemTimeToFileTime(&systime, &systime_filetime);
    systime_lu.LowPart = systime_filetime.dwLowDateTime;
    systime_lu.HighPart = systime_filetime.dwHighDateTime;

    ULONGLONG ms_since_boot = GetTickCount();
    ULONGLONG boottime_10ns = systime_lu.QuadPart - ms_since_boot * 10000;
    boottime_lu.QuadPart = boottime_10ns;
    boottime_filetime.dwLowDateTime = boottime_lu.LowPart;
    boottime_filetime.dwHighDateTime = boottime_lu.HighPart;
    FileTimeToSystemTime(&boottime_filetime, &boottime);

    ULONGLONG uptime_days = ms_since_boot / DAY;
    ULONGLONG uptime_hours = (ms_since_boot % DAY) / HOUR;
    ULONGLONG uptime_minutes = (ms_since_boot % HOUR) / MINUTE;

    snprintf(out, OUTPUTS_BUF_SIZE, "up %llu days, %02llu:%02llu, since %u-%02u-%02u %02u:%02u:%02u\n",
             uptime_days, uptime_hours, uptime_minutes,
             boottime.wYear, boottime.wMonth, boottime.wDay, boottime.wHour, boottime.wMinute, boottime.wSecond);
}

void clientlog() {
    TCHAR resbuf[4 * OUTPUTS_BUF_SIZE + REBOOTLOG_BUF_SIZE + 1];

    TCHAR date_res[OUTPUTS_BUF_SIZE];
    date(date_res);

    LPCTSTR osversion_res = osversion();

    TCHAR uptime_res[OUTPUTS_BUF_SIZE];
    uptime(uptime_res);

    TCHAR ports_res[OUTPUTS_BUF_SIZE];
    port_usage(ports_res);

    /*
    TCHAR rebootlog_res[REBOOTLOG_BUF_SIZE];
    int rebootlogWritten = 0;
    struct restart_event *restart = recent_restarts(5), *restartNext;
    rebootlogWritten += snprintf(rebootlog_res, REBOOTLOG_BUF_SIZE, "%-20s\t%-24s\t%s\n", "Date", "User", "Reason");
    while (restart && rebootlogWritten < REBOOTLOG_BUF_SIZE) {
        rebootlogWritten += snprintf(&rebootlog_res[rebootlogWritten], REBOOTLOG_BUF_SIZE - rebootlogWritten,
                                     "%u-%02u-%02u %02u:%02u:%02u\t%-24s\t%s\n",
                                     restart->wYear, restart->wMonth, restart->wDay,
                                     restart->wHour, restart->wMinute, restart->wSecond,
                                     restart->sUser, restart->sReason);

        restartNext = restart->next;
        big_free("restart event (clientlog)", restart);
        restart = restartNext;
    }
    */

    snprintf(resbuf, sizeof(resbuf),
             "[date]\n%s\n[osversion]\n%s\n[uptime]\n%s\n[ports]\n%s\n[reboots]\n%s",
             date_res, osversion_res, uptime_res, ports_res, "REMOVED FOR DEBUG");
    mrsend(mrmachine, "clientlog", "green", resbuf);
}