#include "clientlog.h"
#include <math.h>

void clog_winmemory(clog_Arena scratch) {
    MEMORYSTATUSEX memoryStatus;

    memoryStatus.dwLength = sizeof(memoryStatus);

    GlobalMemoryStatusEx(&memoryStatus);
    CHAR totalPhys[16], freePhys[16], usedPhys[16];
    ULONGLONG totalPhysicalBytes = memoryStatus.ullTotalPhys;
    ULONGLONG freePhysicalBytes = memoryStatus.ullAvailPhys;
    ULONGLONG usedPhysicalBytes = memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys;
    DOUBLE percentPhysicalUsed = 100.0 * usedPhysicalBytes / totalPhysicalBytes;

    CHAR totalPage[16], freePage[16], usedPage[16];
    ULONGLONG totalPagefileBytes = memoryStatus.ullTotalPageFile;
    ULONGLONG freePagefileBytes = memoryStatus.ullAvailPageFile;
    ULONGLONG usedPagefileBytes = memoryStatus.ullTotalPageFile - memoryStatus.ullAvailPageFile;
    DOUBLE percentPagefileUsed = 100.0 * usedPagefileBytes / totalPagefileBytes;

    clog_ArenaAppend(&scratch, "[winmemory]");
    clog_ArenaAppend(&scratch, "\n%8s  %-13s\t%-15s\t%-15s\t%-15s", "", "TOTAL", "USED", "FREE", "MEMORY USAGE");
    clog_ArenaAppend(&scratch, "\n%8s  %-13s\t%-15s\t%-15s\t%-.2lf%%", "Physical", clog_utils_PrettyBytes(totalPhysicalBytes, 0, totalPhys), clog_utils_PrettyBytes(usedPhysicalBytes, 2, usedPhys), clog_utils_PrettyBytes(freePhysicalBytes, 2, freePhys), percentPhysicalUsed);
    clog_ArenaAppend(&scratch, "\n%8s  %-13s\t%-15s\t%-15s\t%-.2lf%%", "Pagefile", clog_utils_PrettyBytes(totalPagefileBytes, 0, totalPage), clog_utils_PrettyBytes(usedPagefileBytes, 2, usedPage), clog_utils_PrettyBytes(freePagefileBytes, 2, freePage), percentPagefileUsed);
}

#ifdef STANDALONE
int main(int argc, TCHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_winmemory(st->Memory);
    printf("%s", st->Start);
}
#endif