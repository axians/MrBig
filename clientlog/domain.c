#include "clientlog.h"
#include <lm.h>
#include <wchar.h>
#define SECURITY_WIN32
#include <secext.h>
#include <winnt.h>

char *GetDomainFromFqdn(const char *fqdn)
{
    const char *dot = strchr(fqdn, '.');
    if (!dot)
        return NULL;

    return _strdup(dot + 1);
}

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

    clog_ArenaAppend(&scratch, "\n%13s:\t%s", "PartOfDomain", partOfDomain ? "True" : "False");
    clog_ArenaAppend(&scratch, "\n%13s:\t%s", "NetBiosDomain", domainName);

    CHAR hostName[256] = {0};
    DWORD hostNameLen = lengthof(hostName);
    GetComputerNameA(hostName, &hostNameLen);

    CHAR fqdn[256] = {0};
    DWORD fqdnLen = lengthof(fqdn);
    if (!GetComputerNameExA(ComputerNameDnsFullyQualified, fqdn, &fqdnLen))
        snprintf(fqdn, sizeof(fqdn), "%s", hostName);

    CHAR upn[256] = {0};
    ULONG len = ARRAYSIZE(upn);

    const CHAR *upnDomain = "";
    if (GetUserNameExA(NameUserPrincipal, upn, &len)) {
        CHAR *at = strchr(upn, '@');
        if (at)
            upnDomain = at + 1;
    }

    if (strlen(upnDomain) == 0)
        upnDomain = GetDomainFromFqdn(fqdn);


    clog_ArenaAppend(&scratch, "\n%13s:\t%s", "UPNDomain", upnDomain);
    clog_ArenaAppend(&scratch, "\n%13s:\t%s", "FQDN", fqdn);
    clog_utils_TrimTrailingNewlines(&scratch, NULL);
    clog_ArenaAppend(&scratch, "\n");
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x1000);
    clog_domain(st->Memory);
    printf("%s", st->Start);
}
#endif
