

#include "clientlog.h"
#include <winnt.h>

#if STANDALONE
#undef LOG_DEBUG
#define LOG_DEBUG(...) \
    printf("\n" __VA_ARGS__);

#endif

void clog_cpuinfo(clog_Arena scratch) {

    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buffer =
        (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)malloc(len);

    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &len))

    {

        clog_ArenaAppend(&scratch, "(Unable to get logical processor information)\n");
        LOG_DEBUG("cpuinfo.c\tError: %lu\n", GetLastError());
        free(buffer);
        return;
    }

    DWORD offset = 0;

    int coreCount = 0;

    LOG_DEBUG("cpuinfo.c\tGetting Cores\n");
    while (offset < len)
    {

        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info =

            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)((BYTE *)buffer + offset);

        coreCount++;

        offset += info->Size;
    }

    LOG_DEBUG("cpuinfo.c\tGetting Packages\n");
    DWORD pkgLen = 0;
    GetLogicalProcessorInformationEx(RelationProcessorPackage, NULL, &pkgLen);
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pkgBuffer =
        (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)malloc(pkgLen);

    int packageCount = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorPackage, pkgBuffer, &pkgLen)) {
        DWORD pkgOffset = 0;
        while (pkgOffset < pkgLen) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info =
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)((BYTE *)pkgBuffer + pkgOffset);
            packageCount++;
            pkgOffset += info->Size;
        }
    }
    free(pkgBuffer);

    LOG_DEBUG("cpuinfo.c\tGetting Threads\n");
    WORD groups = GetActiveProcessorGroupCount();

    DWORD total = 0;
    for (WORD i = 0; i < groups; i++) {
        total += GetActiveProcessorCount(i);
    }


    free(buffer);
    clog_ArenaAppend(&scratch, "[cpuinfo]\n");
    clog_ArenaAppend(&scratch, "     CPU Sockets: %d\n", packageCount);
    if (packageCount > 0) {
        clog_ArenaAppend(&scratch, "Cores per socket: %d\n", coreCount / packageCount);
    } else {
        clog_ArenaAppend(&scratch, "Cores per socket: N/A\n");
    }
    clog_ArenaAppend(&scratch, "     cores total: %d\n", coreCount);
    if (coreCount > 0) {
        clog_ArenaAppend(&scratch, "    SMT per core: %d\n", total / coreCount);
    } else {
        clog_ArenaAppend(&scratch, "    SMT per core: N/A\n");
    }
    clog_ArenaAppend(&scratch, "       SMT total: %d\n\n", total);
    clog_utils_TrimTrailingNewlines(&scratch, NULL);
    clog_ArenaAppend(&scratch, "\n");
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_cpuinfo(st->Memory);
    printf("%s", st->Start);
}

#endif
