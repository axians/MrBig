#include "clientlog.h"

void clog_winroute(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "[winroute]\n");
    clog_utils_RunCmdSynchronously("route print", scratch);
}