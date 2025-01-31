#include "clientlog.h"

void clientlog(char *mrmachine, void (*mrsend)(char *machine, char *message)) {
    clog_ArenaState *arenaState = clog_ArenaMake(0x80000); // 512 KB
    clog_Arena a = arenaState->Memory;

    clog_DeferError(&a, errorcode) {
        LPSTR errormessage = "\n(Clientlog ran into a problem, error code %d)";
        sprintf((char *)arenaState->CurrentStart - 1 - strlen(errormessage), errormessage, errorcode);
        mrsend(mrmachine, (char *) arenaState->Start);
        clog_PopDeferAll(&a);
        clog_ArenaFreeAll(arenaState);
        return;
    }
    
    processes_Handle hProcesses = clog_processes_StartQuery(&a);
    clog_ArenaAppend(&a, "client %s.windows windows\n", mrmachine);

    clog_date(a);
    clog_ArenaAppend(&a, "\n");
    clog_osversion(a);
    clog_ArenaAppend(&a, "\n");
    clog_winuptime(a);
    clog_ArenaAppend(&a, "\n");
    clog_who(5, a);
    clog_ArenaAppend(&a, "\n");
    clog_diskinfo(a);
    clog_ArenaAppend(&a, "\n");
    clog_winmemory(a);
    clog_ArenaAppend(&a, "\n");
    clog_ipconfig(a);
    clog_ArenaAppend(&a, "\n");
    clog_winroute(a);
    clog_ArenaAppend(&a, "\n");
    clog_winports(a);
    clog_ArenaAppend(&a, "\n");
    clog_processes_EndAppendQuery(hProcesses, &a);
    clog_runningservices(a);
    clog_ArenaAppend(&a, "\n");
    clog_eventlog(5, a);
    clog_ArenaAppend(&a, "\n");
    clog_applications(a);
    clog_ArenaAppend(&a, "\n");
    clog_certificates(a);
    clog_reboots(5, a);
    clog_ArenaAppend(&a, "\n");
    clog_clock(a);

    mrsend(mrmachine, (char *) arenaState->Start);
    clog_PopDeferAll(&a);
    clog_ArenaFreeAll(arenaState);
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