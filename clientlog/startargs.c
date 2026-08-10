#include "clientlog.h"

#ifdef STANDALONE
static int standalone_start_argc = 0;
static char **standalone_start_argv = NULL;

void clog_set_start_args(int argc, char **argv) {
    standalone_start_argc = argc;
    standalone_start_argv = argv;
}

int clog_get_start_argc(void) {
    return standalone_start_argc;
}

char **clog_get_start_argv(void) {
    return standalone_start_argv;
}
#endif

void clog_startargs(clog_Arena scratch) {
    int i;
    int argc = clog_get_start_argc();
    char **argv = clog_get_start_argv();
    LPCSTR rawCmd = GetCommandLineA();

    clog_ArenaAppend(&scratch, "[startargs]");
    clog_ArenaAppend(&scratch, "\n%13s:\t%s", "RawCommandLine", rawCmd ? rawCmd : "(unavailable)");
    clog_ArenaAppend(&scratch, "\n%13s:\t%d", "ParsedArgc", argc);

    if (argv == NULL || argc <= 0) {
        clog_ArenaAppend(&scratch, "\n%13s:\t%s", "ParsedArgs", "(unavailable)");
        return;
    }

    for (i = 0; i < argc; i++) {
        char label[32];
        snprintf(label, sizeof(label), "Arg%d", i);
        clog_ArenaAppend(&scratch, "\n%13s:\t%s", label, argv[i] ? argv[i] : "");
    }
}

#ifdef STANDALONE
int main(int argc, char *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x1000);
    clog_set_start_args(argc, argv);
    clog_startargs(st->Memory);
    printf("%s", st->Start);
    return 0;
}
#endif
