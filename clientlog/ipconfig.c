#include "clientlog.h"

void clog_ipconfig(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "[ipconfig]");
    clog_utils_RunCmdSynchronously("C:\\Windows\\System32\\ipconfig.exe /all", scratch);
    clog_ArenaAppend(&scratch, "\n");
}
