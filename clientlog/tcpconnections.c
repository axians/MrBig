#include <winsock2.h>
#include "clientlog.h"
#include <iphlpapi.h>
#include <tlhelp32.h>

/* TCP analyzer using Windows IP Helper API (no shelling out to netstat). */

#define TCPCONNECTIONS_DEFAULT_EPHEMERAL_START 49152
#define TCPCONNECTIONS_DEFAULT_EPHEMERAL_COUNT 16384
/* Toggle to disable dns lookups if it takes too long */
#define TCPCONNECTIONS_ENABLE_REVERSE_DNS 1

typedef enum {
    tcpconnections_DirectionIncoming = 1,
    tcpconnections_DirectionOutgoing,
    tcpconnections_DirectionUnknown,
} tcpconnections_Direction;

typedef struct {
    CHAR LocalAddress[64];
    CHAR RemoteAddress[64];
    CHAR RemoteFqdn[256];
    DWORD LocalPort;
    DWORD RemotePort;
    DWORD Pid;
    CHAR ProcessName[260];
    tcpconnections_Direction Direction;
} tcpconnections_Established;

typedef struct {
    DWORD Port;
    DWORD Count;
} tcpconnections_PortSummary;

typedef struct {
    CHAR Ip[64];
    CHAR Fqdn[256];
} tcpconnections_RemoteHostCache;

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

static BOOL tcpconnections_GetProcessName(DWORD pid, CHAR *out, size_t outSize) {
    if (outSize == 0) return FALSE;

    snprintf(out, outSize, "Unknown");

    if (pid == 0) {
        snprintf(out, outSize, "System");
        return TRUE;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    BOOL success = FALSE;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                snprintf(out, outSize, "%s", pe32.szExeFile);
                success = TRUE;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32) && !success);
    }

    CloseHandle(hSnapshot);
    return success;
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
        993, 995, 1433, 1984, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 9000, 12202
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
    case 1984: return "MrBig";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5432: return "PostgreSQL";
    case 5985: return "WinRM-HTTP";
    case 5986: return "WinRM-HTTPS";
    case 8080: return "HTTP-Alt";
    case 8443: return "HTTPS-Alt";
    case 9000: return "Axians-Proxy-switch-name";
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

static void tcpconnections_ResolveRemoteHostFqdn(const CHAR *remoteIp, CHAR *out, size_t outSize) {
    if (outSize == 0) return;

#if TCPCONNECTIONS_ENABLE_REVERSE_DNS
    unsigned long addr = inet_addr(remoteIp);
    if (addr != INADDR_NONE) {
        struct hostent *host = gethostbyaddr((const char *)&addr, sizeof(addr), AF_INET);
        if (host != NULL && host->h_name != NULL && host->h_name[0] != '\0') {
            snprintf(out, outSize, "%s", host->h_name);
            return;
        }
    }
#endif

    snprintf(out, outSize, "%s", remoteIp);
}

void clog_tcp_connections(clog_Arena scratch) {
    // Capture run timestamp and constants used by the direction heuristic.
    SYSTEMTIME t;
    GetLocalTime(&t);
    CHAR nowBuf[32];
    clog_utils_PrettySystemtime(&t, clog_utils_TIMESTAMP_DATETIME, nowBuf, sizeof(nowBuf));

    DWORD ephemeralStart = TCPCONNECTIONS_DEFAULT_EPHEMERAL_START;
    DWORD ephemeralCount = TCPCONNECTIONS_DEFAULT_EPHEMERAL_COUNT;
    DWORD ephemeralEnd = ephemeralStart + ephemeralCount - 1;

    // Read the current TCP IPv4 table once and fail fast if unavailable.
    MIB_TCPTABLE_OWNER_PID *tcp4 = tcpconnections_GetTcp4Table();
    if (tcp4 == NULL) {
        clog_ArenaAppend(&scratch, "[tcp_connections]\n(Unable to read TCP table)");
        return;
    }

    // Build a set of listening ports to help classify direction later.
    DWORD listeningPorts[2048] = {0};
    DWORD listeningPortCount = 0;
    for (DWORD i = 0; i < tcp4->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &tcp4->table[i];
        if (r->dwState != MIB_TCP_STATE_LISTEN) continue;
        tcpconnections_AddUniqueDword(listeningPorts, &listeningPortCount, lengthof(listeningPorts), ntohs((u_short)r->dwLocalPort));
    }

    CHAR localIPv4[128][16] = {0};
    DWORD localIPv4Count = tcpconnections_GetLocalIPv4List(localIPv4, lengthof(localIPv4));

    // Collect established non-local connections for row output + summaries.
    DWORD estabCap = 256;
    DWORD estabCount = 0;
    tcpconnections_Established *established = malloc(sizeof(tcpconnections_Established) * estabCap);
    if (established == NULL) {
        free(tcp4);
        clog_ArenaAppend(&scratch, "[tcp_connections]\n(Unable to allocate memory)");
        return;
    }

    // Small cache to avoid repeated reverse DNS lookups for the same remote IP.
    tcpconnections_RemoteHostCache remoteHostCache[512] = {0};
    DWORD remoteHostCacheCount = 0;

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
        e.Pid = r->dwOwningPid;
        tcpconnections_GetProcessName(r->dwOwningPid, e.ProcessName, sizeof(e.ProcessName));

        if (tcpconnections_ContainsDword(listeningPorts, listeningPortCount, e.LocalPort)) {
            e.Direction = tcpconnections_DirectionIncoming;
        } else if (tcpconnections_IsCommonServerPort(e.RemotePort)
                   || e.RemotePort < 1024*2
                   || (e.LocalPort >= ephemeralStart && e.LocalPort <= ephemeralEnd)) {
            e.Direction = tcpconnections_DirectionOutgoing;
        } else {
            e.Direction = tcpconnections_DirectionUnknown;
        }

        BOOL cacheHit = FALSE;
        for (DWORD j = 0; j < remoteHostCacheCount; j++) {
            if (strcmp(remoteHostCache[j].Ip, e.RemoteAddress) == 0) {
                snprintf(e.RemoteFqdn, sizeof(e.RemoteFqdn), "%s", remoteHostCache[j].Fqdn);
                cacheHit = TRUE;
                break;
            }
        }
        if (!cacheHit) {
            tcpconnections_ResolveRemoteHostFqdn(e.RemoteAddress, e.RemoteFqdn, sizeof(e.RemoteFqdn));
            if (remoteHostCacheCount < lengthof(remoteHostCache)) {
                snprintf(remoteHostCache[remoteHostCacheCount].Ip, sizeof(remoteHostCache[remoteHostCacheCount].Ip), "%s", e.RemoteAddress);
                snprintf(remoteHostCache[remoteHostCacheCount].Fqdn, sizeof(remoteHostCache[remoteHostCacheCount].Fqdn), "%s", e.RemoteFqdn);
                remoteHostCacheCount++;
            }
        }

        established[estabCount++] = e;
    }

    // Compute directional totals for the report header.
    DWORD incomingCount = 0, outgoingCount = 0, unknownCount = 0;
    for (DWORD i = 0; i < estabCount; i++) {
        if (established[i].Direction == tcpconnections_DirectionIncoming) incomingCount++;
        else if (established[i].Direction == tcpconnections_DirectionOutgoing) outgoingCount++;
        else unknownCount++;
    }

    // Build and sort remote-port usage summary.
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

    // Emit summary section and detailed per-connection rows.
    clog_ArenaAppend(&scratch, "[tcp_connections]");
    clog_ArenaAppend(&scratch, "\nTCP Analyzer report (source: Windows API)");
    clog_ArenaAppend(&scratch, "\nRunDateTime: %s", nowBuf);
    clog_ArenaAppend(&scratch, "\nEphemeral Port Range: %lu-%lu (%lu ports)", ephemeralStart, ephemeralEnd, ephemeralCount);
    clog_ArenaAppend(&scratch, "\nTotal Connections: %lu", estabCount);
    clog_ArenaAppend(&scratch, "\nIncoming Connections: %lu", incomingCount);
    clog_ArenaAppend(&scratch, "\nOutgoing Connections: %lu", outgoingCount);
    clog_ArenaAppend(&scratch, "\nUnknown Direction: %lu", unknownCount);

    clog_ArenaAppend(&scratch, "\n\n[tcp_connections_rows]");
    clog_ArenaAppend(&scratch, "\n%-15s  %-10s  %-8s  %-31s  %-40s  %-17s  %-12s  %-40s  %-17s  %-16s",
                     "host_name",
                     "direction",
                     "pid",
                     "process_name",
                     "source_fqdn",
                     "source_ip",
                     "source_port",
                     "target_fqdn",
                     "target_ip",
                     "target_port");
    for (DWORD i = 0; i < estabCount; i++) {
        const tcpconnections_Established *e = &established[i];
        const CHAR *sourceFqdn = fqdn;
        const CHAR *sourceIp = e->LocalAddress;
        DWORD sourcePort = e->LocalPort;
        const CHAR *targetFqdn = e->RemoteFqdn;
        const CHAR *targetIp = e->RemoteAddress;
        DWORD targetPort = e->RemotePort;

        if (e->Direction == tcpconnections_DirectionIncoming) {
            sourceFqdn = e->RemoteFqdn;
            sourceIp = e->RemoteAddress;
            sourcePort = e->RemotePort;
            targetFqdn = fqdn;
            targetIp = e->LocalAddress;
            targetPort = e->LocalPort;
        }

        clog_ArenaAppend(&scratch, "\n%-15.15s  %-10.10s  %-8lu  %-31.31s  %-40.120s  %-17.17s  %-12lu  %-40.120s  %-17.17s  %-16lu",
                         hostName,
                         tcpconnections_DirectionLabel(e->Direction),
                         e->Pid,
                         e->ProcessName,
                         sourceFqdn,
                         sourceIp,
                         sourcePort,
                         targetFqdn,
                         targetIp,
                         targetPort);
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
