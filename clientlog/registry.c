
#include "arena.h"
#include "clientlog.h"

// Needs to read from a config file to determine which registry keys to read


void clog_registry(clog_Arena scratch) {



    clog_ArenaAppend(&scratch, "[registry]");



}


#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x20000);
    clog_registry(5, st->Memory);
    printf("%s", st->Start);
}
#endif
