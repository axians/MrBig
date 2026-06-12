#include "clientlog.h"
#include <lm.h>

void clog_domain(clog_Arena scratch) {
    clog_ArenaAppend(&scratch, "[domain]");

    LPWSTR nameBuf = NULL;
    NETSETUP_JOIN_STATUS joinStatus;
    NET_API_STATUS status = NetGetJoinInformation(NULL, &nameBuf, &joinStatus);

    if (status != NERR_Success) {
        clog_ArenaAppend(&scratch, "\n(Unable to get domain information)");
        return;
    }

    BOOL partOfDomain = (joinStatus == NetSetupDomainName);
    CHAR domainName[256] = "(None)";
    if (nameBuf && nameBuf[0] != L'\0')
        wcstombs(domainName, nameBuf, sizeof(domainName) - 1);
    NetApiBufferFree(nameBuf);

    clog_ArenaAppend(&scratch, "\n%12s:\t%s", "Domain", domainName);
    clog_ArenaAppend(&scratch, "\n%12s:\t%s", "PartOfDomain", partOfDomain ? "True" : "False");
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x1000);
    clog_domain(st->Memory);
    printf("%s", st->Start);
}
#endif
