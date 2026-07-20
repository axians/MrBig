#include "clientlog.h"

void clog_winroute(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "[winroute]\n");
    clog_utils_RunCmdSynchronously("C:\\Windows\\System32\\route print", scratch);
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_winroute(st->Memory);
    printf("%s", st->Start);
}
#endif
