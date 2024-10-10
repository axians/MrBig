#include "clientlog.h"

void clog_ipconfig(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "[ipconfig]\n");
    clog_utils_RunCmdSynchronously("ipconfig /all", scratch);
}