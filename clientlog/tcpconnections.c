#include "clientlog.h"
#include <iphlpapi.h>

/* TCP analyzer using Windows IP Helper API (no shelling out to netstat). */

#define TCPCONNECTIONS_DEFAULT_EPHEMERAL_START 49152
#define TCPCONNECTIONS_DEFAULT_EPHEMERAL_COUNT 16384

typedef enum {
    tcpconnections_DirectionIncoming = 1,
    tcpconnections_DirectionOutgoing,
    tcpconnections_DirectionUnknown,
} tcpconnections_Direction;

typedef struct {
    CHAR LocalAddress[64];
    CHAR RemoteAddress[64];
    CHAR State[32];
    DWORD LocalPort;
    DWORD RemotePort;
    tcpconnections_Direction Direction;
} tcpconnections_Established;

typedef struct {
    DWORD Port;
    DWORD Count;
} tcpconnections_PortSummary;

static BOOL tcpconnections_ContainsDword(const DWORD *arr, DWORD len, DWORD value) {
    for (DWORD i = 0; i < len; i++) {
        if (arr[i] == value) return TRUE;
    }
    return FALSE;
}

static void tcpconnections_AddUniqueDword(DWORD *arr, DWORD *len, DWORD maxLen, DWORD value) {
    if (tcpconnections_ContainsDword(arr, *len, value)) return;
    if (*len < maxLen) {
        arr[*len] = value;
        (*len)++;
    }
}

static DWORD tcpconnections_GetLocalIPv4List(CHAR ips[][16], DWORD maxIps) {
    DWORD count = 0;
    if (count < maxIps) {
        snprintf(ips[count++], 16, "127.0.0.1");
    }

    ULONG size = 0;
    if (GetAdaptersInfo(NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        return count;
    }

    PIP_ADAPTER_INFO adapters = malloc(size);
    if (adapters == NULL) return count;

    if (GetAdaptersInfo(adapters, &size) == NO_ERROR) {
        for (PIP_ADAPTER_INFO p = adapters; p != NULL; p = p->Next) {
            for (IP_ADDR_STRING *addr = &p->IpAddressList; addr != NULL; addr = addr->Next) {
                if (count >= maxIps) break;
                if (addr->IpAddress.String[0] == '\0') continue;
                if (strcmp(addr->IpAddress.String, "0.0.0.0") == 0) continue;

                BOOL exists = FALSE;
                for (DWORD i = 0; i < count; i++) {
                    if (strcmp(ips[i], addr->IpAddress.String) == 0) {
                        exists = TRUE;
                        break;
                    }
                }
                if (!exists) {
                    snprintf(ips[count++], 16, "%s", addr->IpAddress.String);
                }
            }
        }
    }

    free(adapters);
    return count;
}

static BOOL tcpconnections_IsCommonServerPort(DWORD port) {
    static DWORD commonServerPorts[] = {
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
        993, 995, 1433, 3306, 3389, 5432, 5985, 5986, 8080, 8443,
    };
    return tcpconnections_ContainsDword(commonServerPorts, lengthof(commonServerPorts), port);
}

static const CHAR *tcpconnections_DirectionLabel(tcpconnections_Direction direction) {
    switch (direction) {
    case tcpconnections_DirectionIncoming:
        return "Incoming";
    case tcpconnections_DirectionOutgoing:
        return "Outgoing";
    default:
        return "Unknown";
    }
}

static const CHAR *tcpconnections_ServiceName(DWORD port) {
    switch (port) {
    case 21: return "FTP";
    case 22: return "SSH";
    case 23: return "Telnet";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 80: return "HTTP";
    case 110: return "POP3";
    case 135: return "RPC";
    case 143: return "IMAP";
    case 389: return "LDAP";
    case 443: return "HTTPS";
    case 445: return "SMB";
    case 465: return "SMTPS";
    case 587: return "SMTP-Submission";
    case 636: return "LDAPS";
    case 993: return "IMAPS";
    case 995: return "POP3S";
    case 1433: return "MS-SQL";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5432: return "PostgreSQL";
    case 5985: return "WinRM-HTTP";
    case 5986: return "WinRM-HTTPS";
    case 8080: return "HTTP-Alt";
    case 8443: return "HTTPS-Alt";
    case 12202: return "Graylog";
    default: return "Unknown";
    }
}

static int tcpconnections_ComparePortSummary(const void *a, const void *b) {
    const tcpconnections_PortSummary *left = (const tcpconnections_PortSummary *)a;
    const tcpconnections_PortSummary *right = (const tcpconnections_PortSummary *)b;
    if (left->Count < right->Count) return 1;
    if (left->Count > right->Count) return -1;
    if (left->Port > right->Port) return 1;
    if (left->Port < right->Port) return -1;
    return 0;
}

static MIB_TCPTABLE_OWNER_PID *tcpconnections_GetTcp4Table(void) {
    DWORD size = 0;
    DWORD status = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER) return NULL;

    MIB_TCPTABLE_OWNER_PID *table = malloc(size);
    if (table == NULL) return NULL;

    status = GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != NO_ERROR) {
        free(table);
        return NULL;
    }
    return table;
}

void clog_tcp_connections(clog_Arena scratch) {
    SYSTEMTIME t;
    GetLocalTime(&t);
    CHAR nowBuf[32];
    clog_utils_PrettySystemtime(&t, clog_utils_TIMESTAMP_DATETIME, nowBuf, sizeof(nowBuf));

    DWORD ephemeralStart = TCPCONNECTIONS_DEFAULT_EPHEMERAL_START;
    DWORD ephemeralCount = TCPCONNECTIONS_DEFAULT_EPHEMERAL_COUNT;
    DWORD ephemeralEnd = ephemeralStart + ephemeralCount - 1;

    MIB_TCPTABLE_OWNER_PID *tcp4 = tcpconnections_GetTcp4Table();
    if (tcp4 == NULL) {
        clog_ArenaAppend(&scratch, "[tcp_connections]\n(Unable to read TCP table)");
        return;
    }

    DWORD listeningPorts[2048] = {0};
    DWORD listeningPortCount = 0;
    for (DWORD i = 0; i < tcp4->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &tcp4->table[i];
        if (r->dwState != MIB_TCP_STATE_LISTEN) continue;
        tcpconnections_AddUniqueDword(listeningPorts, &listeningPortCount, lengthof(listeningPorts), ntohs((u_short)r->dwLocalPort));
    }

    CHAR localIPv4[128][16] = {0};
    DWORD localIPv4Count = tcpconnections_GetLocalIPv4List(localIPv4, lengthof(localIPv4));

    DWORD estabCap = 256;
    DWORD estabCount = 0;
    tcpconnections_Established *established = malloc(sizeof(tcpconnections_Established) * estabCap);
    if (established == NULL) {
        free(tcp4);
        clog_ArenaAppend(&scratch, "[tcp_connections]\n(Unable to allocate memory)");
        return;
    }

    for (DWORD i = 0; i < tcp4->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &tcp4->table[i];
        if (r->dwState != MIB_TCP_STATE_ESTAB) continue;

        struct in_addr localAddr, remoteAddr;
        localAddr.S_un.S_addr = (u_long)r->dwLocalAddr;
        remoteAddr.S_un.S_addr = (u_long)r->dwRemoteAddr;

        CHAR localBuf[64] = {0}, remoteBuf[64] = {0};
        snprintf(localBuf, sizeof(localBuf), "%s", inet_ntoa(localAddr));
        snprintf(remoteBuf, sizeof(remoteBuf), "%s", inet_ntoa(remoteAddr));

        if (strcmp(localBuf, "127.0.0.1") == 0 && strcmp(remoteBuf, "127.0.0.1") == 0) continue;
        if (strcmp(localBuf, remoteBuf) == 0) continue;

        BOOL remoteIsLocal = FALSE;
        for (DWORD j = 0; j < localIPv4Count; j++) {
            if (strcmp(localIPv4[j], remoteBuf) == 0) {
                remoteIsLocal = TRUE;
                break;
            }
        }
        if (remoteIsLocal) continue;

        if (estabCount == estabCap) {
            DWORD nextCap = estabCap * 2;
            tcpconnections_Established *nextEstablished = realloc(established, sizeof(tcpconnections_Established) * nextCap);
            if (nextEstablished == NULL) break;
            established = nextEstablished;
            estabCap = nextCap;
        }

        tcpconnections_Established e;
        ZeroMemory(&e, sizeof(e));
        snprintf(e.LocalAddress, sizeof(e.LocalAddress), "%s", localBuf);
        snprintf(e.RemoteAddress, sizeof(e.RemoteAddress), "%s", remoteBuf);
        e.LocalPort = ntohs((u_short)r->dwLocalPort);
        e.RemotePort = ntohs((u_short)r->dwRemotePort);
        snprintf(e.State, sizeof(e.State), "%s", "ESTABLISHED");

        if (tcpconnections_ContainsDword(listeningPorts, listeningPortCount, e.LocalPort)) {
            e.Direction = tcpconnections_DirectionIncoming;
        } else if (tcpconnections_IsCommonServerPort(e.RemotePort)
                   || e.RemotePort < 1024
                   || (e.LocalPort >= ephemeralStart && e.LocalPort <= ephemeralEnd)) {
            e.Direction = tcpconnections_DirectionOutgoing;
        } else {
            e.Direction = tcpconnections_DirectionUnknown;
        }

        established[estabCount++] = e;
    }

    DWORD incomingCount = 0, outgoingCount = 0, unknownCount = 0;
    for (DWORD i = 0; i < estabCount; i++) {
        if (established[i].Direction == tcpconnections_DirectionIncoming) incomingCount++;
        else if (established[i].Direction == tcpconnections_DirectionOutgoing) outgoingCount++;
        else unknownCount++;
    }

    tcpconnections_PortSummary portSummary[1024] = {0};
    DWORD portSummaryCount = 0;
    for (DWORD i = 0; i < estabCount; i++) {
        DWORD found = portSummaryCount;
        for (DWORD j = 0; j < portSummaryCount; j++) {
            if (portSummary[j].Port == established[i].RemotePort) {
                found = j;
                break;
            }
        }
        if (found == portSummaryCount) {
            if (portSummaryCount >= lengthof(portSummary)) continue;
            portSummary[portSummaryCount].Port = established[i].RemotePort;
            portSummary[portSummaryCount].Count = 1;
            portSummaryCount++;
        } else {
            portSummary[found].Count++;
        }
    }
    qsort(portSummary, portSummaryCount, sizeof(portSummary[0]), tcpconnections_ComparePortSummary);

    CHAR hostName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hostNameLen = lengthof(hostName);
    if (!GetComputerName(hostName, &hostNameLen)) {
        snprintf(hostName, sizeof(hostName), "UnknownHost");
    }

    CHAR fqdn[256] = {0};
    DWORD fqdnLen = lengthof(fqdn);
    if (!GetComputerNameEx(ComputerNameDnsFullyQualified, fqdn, &fqdnLen)) {
        snprintf(fqdn, sizeof(fqdn), "%s", hostName);
    }

    clog_ArenaAppend(&scratch, "[tcp_connections]");
    clog_ArenaAppend(&scratch, "\nTCP Analyzer report (source: Windows IP Helper API)");
    clog_ArenaAppend(&scratch, "\nRunDateTime: %s", nowBuf);
    clog_ArenaAppend(&scratch, "\nEphemeral Port Range: %lu-%lu (%lu ports)", ephemeralStart, ephemeralEnd, ephemeralCount);
    clog_ArenaAppend(&scratch, "\nTotal Connections: %lu", estabCount);
    clog_ArenaAppend(&scratch, "\nIncoming Connections: %lu", incomingCount);
    clog_ArenaAppend(&scratch, "\nOutgoing Connections: %lu", outgoingCount);
    clog_ArenaAppend(&scratch, "\nUnknown Direction: %lu", unknownCount);

    clog_ArenaAppend(&scratch, "\n\n[tcp_connections_rows]");
    clog_ArenaAppend(&scratch, "\n%-19s  %-15s  %-28s  %-10s  %-17s  %-12s  %-17s  %-16s  %-13s",
                     "run_datetime",
                     "host_name",
                     "local_fqdn",
                     "direction",
                     "source_ip",
                     "source_port",
                     "destination_ip",
                     "destination_port",
                     "state");
    for (DWORD i = 0; i < estabCount; i++) {
        const tcpconnections_Established *e = &established[i];
        const CHAR *sourceIp = e->LocalAddress;
        DWORD sourcePort = e->LocalPort;
        const CHAR *destinationIp = e->RemoteAddress;
        DWORD destinationPort = e->RemotePort;

        if (e->Direction == tcpconnections_DirectionIncoming) {
            sourceIp = e->RemoteAddress;
            sourcePort = e->RemotePort;
            destinationIp = e->LocalAddress;
            destinationPort = e->LocalPort;
        }

        clog_ArenaAppend(&scratch, "\n%-19.19s  %-15.15s  %-28.28s  %-10.10s  %-17.17s  %-12lu  %-17.17s  %-16lu  %-13.13s",
                         nowBuf,
                         hostName,
                         fqdn,
                         tcpconnections_DirectionLabel(e->Direction),
                         sourceIp,
                         sourcePort,
                         destinationIp,
                         destinationPort,
                         e->State);
    }

    DWORD topPorts = min(portSummaryCount, 10u);
    clog_ArenaAppend(&scratch, "\n\n[tcp_connections_port_summary]");
    clog_ArenaAppend(&scratch, "\n%-10s\t%-8s\t%-18s", "RemotePort", "Count", "Service");
    for (DWORD i = 0; i < topPorts; i++) {
        clog_ArenaAppend(&scratch, "\n%-10lu\t%-8lu\t%-18s",
                         portSummary[i].Port,
                         portSummary[i].Count,
                         tcpconnections_ServiceName(portSummary[i].Port));
    }

    free(established);
    free(tcp4);
}

#ifdef STANDALONE
int main(void) {
    clog_ArenaState *st = clog_ArenaMake(0x100000);
    clog_tcp_connections(st->Memory);
    printf("%s", st->Start);
    clog_ArenaFreeAll(st);
    return 0;
}
#endif