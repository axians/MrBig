#include "clientlog.h"

#define LOG_DEBUG(...) if (mrlog) { mrlog(__VA_ARGS__); }

void clientlog(char *mrmachine, void (*mrsend)(char *machine, char *message), void (*mrlog)(char *, ...)) {
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_ArenaState *arenaState = clog_ArenaMake(0x80000); // 512 KB
    clog_Arena a = arenaState->Memory;

    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_DeferError(&a, errorcode) {
        LPSTR errormessage = "\n(Clientlog ran into a problem, error code %d)";
        sprintf((char *)arenaState->CurrentStart - 1 - strlen(errormessage), errormessage, errorcode);
        mrsend(mrmachine, (char *) arenaState->Start);
        clog_PopDeferAll(&a);
        clog_ArenaFreeAll(arenaState);
        return;
    }

    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    processes_Handle hProcesses = clog_processes_StartQuery(&a);
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_ArenaAppend(&a, "client %s.windows windows\n", mrmachine);

    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_date(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_osversion(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_winuptime(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_who(5, a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_diskinfo(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_winmemory(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_ipconfig(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_winroute(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_winports(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_processes_EndAppendQuery(hProcesses, &a);
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_runningservices(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_eventlog(5, a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_applications(a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_certificates(a);
    clog_reboots(5, a);
    clog_ArenaAppend(&a, "\n");
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_clock(a);

    mrsend(mrmachine, (char *)arenaState->Start);
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
    clog_PopDeferAll(&a);
    clog_ArenaFreeAll(arenaState);
    LOG_DEBUG("Clientlog: Line %d", __LINE__);
}

#ifdef CLIENTLOGEXE
void mrsend(char *machine, char *message) {
    printf("%s", message);
}

int main(int argc, char *argv[]) {
    clientlog("test", &mrsend);
    return 0;
}
#endif