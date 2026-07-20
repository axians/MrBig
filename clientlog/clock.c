#include "clientlog.h"
#include <time.h>

#define TIME_BUF_SIZE 64

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

    strftime(localBuf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S %Z", tm_time);

    CHAR localISOBuf[TIME_BUF_SIZE];
    clock_PrettyIso8601LocalTime(&t, localISOBuf, TIME_BUF_SIZE);

    tm_time = gmtime(&unixtime);
    CHAR systemBuf[TIME_BUF_SIZE];
    strftime(systemBuf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", tm_time);

    clog_ArenaAppend(&scratch, "[clock]");
    clog_ArenaAppend(&scratch, "\nlocal:\t%s", localBuf);
    clog_ArenaAppend(&scratch, "\nISO:\t%s", localISOBuf);
    clog_ArenaAppend(&scratch, "\nUTC:\t%s UTC", systemBuf);
}

#ifdef STANDALONE
int main(int argc, char *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_clock(st->Memory);
    printf("%s", st->Start);
    return 0;
}
#endif
