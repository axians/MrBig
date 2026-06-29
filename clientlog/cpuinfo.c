

#include "clientlog.h"
#include <winnt.h>

#if STANDALONE
#undef LOG_DEBUG
#define LOG_DEBUG(...) \
    printf("\n" __VA_ARGS__);

#endif

void clog_cpuinfo(clog_Arena scratch) {

    clog_ArenaAppend(&scratch, "[cpu]\n");
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

    LOG_DEBUG("cpuinfo.c\tGetting Threads\n");
    WORD groups = GetActiveProcessorGroupCount();

    DWORD total = 0;
    for (WORD i = 0; i < groups; i++) {
        total += GetActiveProcessorCount(i);
    }


    free(buffer);
    clog_ArenaAppend(&scratch, "    CPU Packages: %d\n", groups);
    clog_ArenaAppend(&scratch, "  Physical Cores: %d\n", coreCount);
    clog_ArenaAppend(&scratch, " Logical Threads: %d\n", total);
    if (coreCount > 0) {
        clog_ArenaAppend(&scratch, "Threads per core: %d\n", total / coreCount);
    }
    else {
        clog_ArenaAppend(&scratch, "Threads per core: N/A\n");
    }
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_cpuinfo(st->Memory);
    printf("%s", st->Start);
}

#endif
