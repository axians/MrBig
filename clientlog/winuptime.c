#include "clientlog.h"
#include <pdh.h>

#define MINUTE 60ULL
#define HOUR   (60ULL * MINUTE)
#define DAY    (24ULL * HOUR)

// Reads the same "System Up Time" perf counter that cpu.c uses via
// read_perfcounters(2, {674}), so the values stay in sync.
static ULONGLONG uptime_seconds(void)
{
    PDH_HQUERY query = NULL;
    PDH_HCOUNTER counter;
    PDH_FMT_COUNTERVALUE val;
    ULONGLONG result = 0;

    if (PdhOpenQuery(NULL, 0, &query) != ERROR_SUCCESS)
        goto done;
    // PdhAddEnglishCounterA resolves the counter name independent of locale
    if (PdhAddEnglishCounterA(query, "\\System\\System Up Time", 0, &counter) != ERROR_SUCCESS)
        goto done;
    // Two collections required by PDH before it will format the value
    PdhCollectQueryData(query);
    PdhCollectQueryData(query);
    if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &val) == ERROR_SUCCESS)
        result = (ULONGLONG)val.doubleValue;
done:
    if (query)
        PdhCloseQuery(query);
    return result;
}

void clog_winuptime(clog_Arena scratch)
{
    ULONGLONG secs = uptime_seconds();

    ULONGLONG uptime_days = secs / DAY;
    ULONGLONG uptime_hours = (secs % DAY) / HOUR;
    ULONGLONG uptime_minutes = (secs % HOUR) / MINUTE;

    // Derive boot time by subtracting uptime from current wall-clock time
    FILETIME now_ft;
    ULARGE_INTEGER now_lu, boot_lu;
    FILETIME boot_ft;
    SYSTEMTIME boottime;
    GetSystemTimeAsFileTime(&now_ft);
    now_lu.LowPart = now_ft.dwLowDateTime;
    now_lu.HighPart = now_ft.dwHighDateTime;
    boot_lu.QuadPart = now_lu.QuadPart - secs * 10000000ULL;
    boot_ft.dwLowDateTime = boot_lu.LowPart;
    boot_ft.dwHighDateTime = boot_lu.HighPart;
    FileTimeToSystemTime(&boot_ft, &boottime);

    clog_ArenaAppend(&scratch, "[winuptime]\n");
    clog_ArenaAppend(&scratch, "up %llu days, %02llu:%02llu, since %u-%02u-%02u %02u:%02u:%02u",
                     uptime_days, uptime_hours, uptime_minutes,
                     boottime.wYear, boottime.wMonth, boottime.wDay,
                     boottime.wHour, boottime.wMinute, boottime.wSecond);
}

#ifdef STANDALONE
int main(int argc, TCHAR *argv[])
{
    clog_ArenaState *st = clog_ArenaMake(100);
    clog_winuptime(st->Memory);
    printf("%s", st->Start);
}
#endif
