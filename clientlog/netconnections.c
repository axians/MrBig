#include <winsock2.h>
#include "clientlog.h"
#include <ctype.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <tlhelp32.h>

/* Toggle to disable reverse DNS lookups if they take too long */
#define NETCONNECTIONS_ENABLE_REVERSE_DNS 1

#define NETCONNECTIONS_MAX_CONNECTIONS 256
#define NETCONNECTIONS_MAX_DNS_CACHE 512
#define NETCONNECTIONS_COL_PORT  5

typedef struct {
    CHAR Time[40];          /* YYYY-MM-DDTHH:MM:SSZ (UTC) */
    CHAR Proto[8];          /* tcp, udp, icmp, ... */
    CHAR SrcIp[48];
    CHAR DstIp[48];
    DWORD SrcPort;
    DWORD DstPort;
    CHAR SrcFqdn[256];
    CHAR DstFqdn[256];
    DWORD Count;
    DWORD Pid;              /* 0 = unknown */
    CHAR ProcessName[64];
} netconnections_Connection;

typedef struct {
    DWORD Port;
    DWORD Pid;
} netconnections_ListenEntry;

typedef struct {
    CHAR Ip[48];
    CHAR Fqdn[256];
} netconnections_DnsCache;

static void netconnections_ResolveFqdn(const CHAR *ip, netconnections_DnsCache *cache,
                                    DWORD *cacheCount, CHAR *out, size_t outSize) {
    if (outSize == 0)
        return;

    for (DWORD i = 0; i < *cacheCount; i++) {
        if (strcmp(cache[i].Ip, ip) == 0) {
            snprintf(out, outSize, "%s", cache[i].Fqdn);
            return;
        }
    }

    CHAR resolved[256];
#if NETCONNECTIONS_ENABLE_REVERSE_DNS
    unsigned long addr = inet_addr(ip);
    if (addr != INADDR_NONE) {
        struct hostent *host = gethostbyaddr((const char *)&addr, sizeof(addr), AF_INET);
        if (host != NULL && host->h_name != NULL && host->h_name[0] != '\0') {
            snprintf(resolved, sizeof(resolved), "%s", host->h_name);
        } else {
            snprintf(resolved, sizeof(resolved), "%s", ip);
        }
    } else {
        snprintf(resolved, sizeof(resolved), "%s", ip);
    }
#else
    snprintf(resolved, sizeof(resolved), "%s", ip);
#endif

    if (*cacheCount < NETCONNECTIONS_MAX_DNS_CACHE) {
        snprintf(cache[*cacheCount].Ip, sizeof(cache[*cacheCount].Ip), "%s", ip);
        snprintf(cache[*cacheCount].Fqdn, sizeof(cache[*cacheCount].Fqdn), "%s", resolved);
        (*cacheCount)++;
    }

    snprintf(out, outSize, "%s", resolved);
}

static DWORD netconnections_BuildListenMap(netconnections_ListenEntry *map, DWORD maxEntries) {
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER)
        return 0;

    MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (table == NULL)
        return 0;

    DWORD count = 0;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries && count < maxEntries; i++) {
            if (table->table[i].dwState != MIB_TCP_STATE_LISTEN)
                continue;
            map[count].Port = ntohs((u_short)table->table[i].dwLocalPort);
            map[count].Pid = table->table[i].dwOwningPid;
            count++;
        }
    }

    free(table);
    return count;
}

static void netconnections_GetProcessName(DWORD pid, CHAR *out, size_t outSize) {
    if (outSize == 0)
        return;
    snprintf(out, outSize, "-");
    if (pid == 0)
        return;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32 pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                snprintf(out, outSize, "%.*s", (int)(outSize - 1), pe.szExeFile);
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void netconnections_LocalToUtcIso8601(const CHAR *date, const CHAR *time_str,
                                             CHAR *out, size_t outSize) {
    if (outSize == 0)
        return;

    SYSTEMTIME local = {0}, utc = {0};
    sscanf(date,     "%hu-%hu-%hu", &local.wYear, &local.wMonth, &local.wDay);
    sscanf(time_str, "%hu:%hu:%hu", &local.wHour, &local.wMinute, &local.wSecond);

    if (!TzSpecificLocalTimeToSystemTime(NULL, &local, &utc)) {
        snprintf(out, outSize, "%sT%s", date, time_str);
        return;
    }

    snprintf(out, outSize, "%04u-%02u-%02uT%02u:%02u:%02uZ",
             utc.wYear, utc.wMonth, utc.wDay,
             utc.wHour, utc.wMinute, utc.wSecond);
}

/*
 * Parse a single firewall log line. Expected whitespace-separated fields (0-indexed):
 *   0=date  1=time  2=action  3=proto  4=src-ip  5=dst-ip  6=src-port  7=dst-port  ...
 *
 * Ports may be "-" for non-TCP/UDP protocols (e.g. ICMP); these are stored as 0.
 * Returns TRUE on success, FALSE if the line cannot be parsed or should be skipped.
 */
static BOOL netconnections_ParseLine(const CHAR *line, netconnections_Connection *conn) {
    CHAR f0[16], f1[12], f2[16], f3[8], f4[48], f5[48], f6[12], f7[12];

    int n = sscanf(line, "%15s %11s %15s %7s %47s %47s %11s %11s",
                   f0, f1, f2, f3, f4, f5, f6, f7);
    if (n < 8)
        return FALSE;

    /* Only process ALLOW entries for TCP/UDP */
    for (CHAR *p = f2; *p; p++)
        *p = (CHAR)toupper((unsigned char)*p);
    if (strcmp(f2, "ALLOW") != 0)
        return FALSE;

    for (CHAR *p = f3; *p; p++)
        *p = (CHAR)tolower((unsigned char)*p);
    if (strcmp(f3, "tcp") != 0 && strcmp(f3, "udp") != 0)
        return FALSE;

    /* Skip lines where IPs are missing, wildcard, loopback, or IPv6 */
    if (strchr(f4, ':') != NULL || strchr(f5, ':') != NULL)
        return FALSE;
    if (strcmp(f4, "::1") == 0 || strcmp(f5, "::1") == 0)
        return FALSE;
    if (f4[0] == '-' || f5[0] == '-')
        return FALSE;
    if (strcmp(f4, "0.0.0.0") == 0 || strcmp(f5, "0.0.0.0") == 0)
        return FALSE;
    if (strncmp(f4, "127.", 4) == 0 || strncmp(f5, "127.", 4) == 0)
        return FALSE;
    if (strcmp(f4, f5) == 0)
        return FALSE;

    netconnections_LocalToUtcIso8601(f0, f1, conn->Time, sizeof(conn->Time));
    snprintf(conn->Proto, sizeof(conn->Proto), "%s", f3);

    snprintf(conn->SrcIp, sizeof(conn->SrcIp), "%s", f4);
    snprintf(conn->DstIp, sizeof(conn->DstIp), "%s", f5);

    conn->SrcPort = (f6[0] != '-') ? (DWORD)strtoul(f6, NULL, 10) : 0;
    conn->DstPort = (f7[0] != '-') ? (DWORD)strtoul(f7, NULL, 10) : 0;
    conn->Count = 1;
    conn->SrcFqdn[0] = '\0';
    conn->DstFqdn[0] = '\0';
    conn->Pid = 0;
    conn->ProcessName[0] = '\0';

    return TRUE;
}

static void netconnections_NormalizeEndpointPair(const netconnections_Connection *conn,
                                                const CHAR **firstIp,
                                                DWORD *firstPort,
                                                const CHAR **secondIp,
                                                DWORD *secondPort) {
    const CHAR *srcIp = conn->SrcIp;
    const CHAR *dstIp = conn->DstIp;
    DWORD srcPort = conn->SrcPort;
    DWORD dstPort = conn->DstPort;

    if (strcmp(srcIp, dstIp) < 0 ||
        (strcmp(srcIp, dstIp) == 0 && srcPort <= dstPort)) {
        *firstIp = srcIp;
        *firstPort = srcPort;
        *secondIp = dstIp;
        *secondPort = dstPort;
    } else {
        *firstIp = dstIp;
        *firstPort = dstPort;
        *secondIp = srcIp;
        *secondPort = srcPort;
    }
}

static BOOL netconnections_ConnectionMatches(const netconnections_Connection *a,
                                            const netconnections_Connection *b) {
    if (strcmp(a->Proto, b->Proto) != 0)
        return FALSE;

    const CHAR *aFirstIp = NULL, *aSecondIp = NULL, *bFirstIp = NULL, *bSecondIp = NULL;
    DWORD aFirstPort = 0, aSecondPort = 0, bFirstPort = 0, bSecondPort = 0;
    netconnections_NormalizeEndpointPair(a, &aFirstIp, &aFirstPort, &aSecondIp, &aSecondPort);
    netconnections_NormalizeEndpointPair(b, &bFirstIp, &bFirstPort, &bSecondIp, &bSecondPort);

    if (strcmp(a->Proto, "udp") == 0) {
        return strcmp(aFirstIp, bFirstIp) == 0 &&
               strcmp(aSecondIp, bSecondIp) == 0;
    }

    return strcmp(aFirstIp, bFirstIp) == 0 && aFirstPort == bFirstPort &&
           strcmp(aSecondIp, bSecondIp) == 0 && aSecondPort == bSecondPort;
}

static BOOL netconnections_ConnectionSameFlow(const netconnections_Connection *a,
                                             const netconnections_Connection *b) {
    if (strcmp(a->Proto, b->Proto) != 0)
        return FALSE;

    if (strcmp(a->SrcIp, b->SrcIp) == 0 &&
        strcmp(a->DstIp, b->DstIp) == 0 &&
        a->DstPort == b->DstPort) {
        return TRUE;
    }

    if (strcmp(a->SrcIp, b->DstIp) == 0 &&
        strcmp(a->DstIp, b->SrcIp) == 0 &&
        a->DstPort == b->SrcPort) {
        return TRUE;
    }

    return FALSE;
}

#define NETCONNECTIONS_STATE_PATH "%TEMP%\\mrbig-netconnections.state"

void clog_net_connections(clog_Arena scratch) {
    CHAR logPath[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(
        "%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log",
        logPath, sizeof(logPath));

    /* Load last-read byte offset from state file */
    CHAR statePath[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(NETCONNECTIONS_STATE_PATH, statePath, sizeof(statePath));

    long lastOffset = 0;
    {
        FILE *sf = fopen(statePath, "r");
        if (sf != NULL) {
            fscanf(sf, "%ld", &lastOffset);
            fclose(sf);
        }
    }

    FILE *fp = fopen(logPath, "r");
    if (fp == NULL) {
        clog_ArenaAppend(&scratch, "[net-connections]\n(Unable to open firewall log: %s)", logPath);
        return;
    }

    /* Seek to last read position; if file was rotated/truncated, start from beginning */
    if (lastOffset > 0) {
        fseek(fp, 0, SEEK_END);
        if (lastOffset <= ftell(fp))
            fseek(fp, lastOffset, SEEK_SET);
        else
            fseek(fp, 0, SEEK_SET);
    }

    netconnections_Connection *conns =
        (netconnections_Connection *)malloc(sizeof(netconnections_Connection) * NETCONNECTIONS_MAX_CONNECTIONS);
    if (conns == NULL) {
        fclose(fp);
        clog_ArenaAppend(&scratch, "[firewalllog]\n(Out of memory)");
        return;
    }

    netconnections_DnsCache *dnsCache =
        (netconnections_DnsCache *)malloc(sizeof(netconnections_DnsCache) * NETCONNECTIONS_MAX_DNS_CACHE);
    if (dnsCache == NULL) {
        free(conns);
        fclose(fp);
        clog_ArenaAppend(&scratch, "[firewalllog]\n(Out of memory)");
        return;
    }

    DWORD connCount = 0;
    DWORD dnsCacheCount = 0;

    CHAR line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\r' || line[0] == '\n')
            continue;

        netconnections_Connection parsed;
        if (!netconnections_ParseLine(line, &parsed))
            continue;

        /*
         * Merge rows that represent the same logical flow even when the firewall log
         * reports the reverse direction or when a short-lived ephemeral source port
         * rotates. This mirrors the updated net-connections dedupe logic.
         */
        BOOL found = FALSE;
        for (DWORD i = 0; i < connCount; i++) {
            if (netconnections_ConnectionMatches(&conns[i], &parsed) ||
                (netconnections_ConnectionSameFlow(&conns[i], &parsed) &&
                 conns[i].Proto[0] == parsed.Proto[0])) {
                conns[i].Count++;
                if (strcmp(conns[i].Time, parsed.Time) < 0)
                    snprintf(conns[i].Time, sizeof(conns[i].Time), "%s", parsed.Time);
                found = TRUE;
                break;
            }
        }

        if (!found && connCount < NETCONNECTIONS_MAX_CONNECTIONS) {
            conns[connCount++] = parsed;
        }
    }
    long currentOffset = ftell(fp);
    fclose(fp);

    /* Persist current file offset for next run */
    {
        FILE *sf = fopen(statePath, "w");
        if (sf != NULL) {
            fprintf(sf, "%ld\n", currentOffset);
            fclose(sf);
        }
    }

    /* For incoming connections, look up the listening PID from the TCP table */
    netconnections_ListenEntry listenMap[1024];
    DWORD listenCount = netconnections_BuildListenMap(listenMap, lengthof(listenMap));

    for (DWORD i = 0; i < connCount; i++) {
        for (DWORD j = 0; j < listenCount; j++) {
            if (listenMap[j].Port == conns[i].DstPort) {
                conns[i].Pid = listenMap[j].Pid;
                netconnections_GetProcessName(conns[i].Pid, conns[i].ProcessName,
                                              sizeof(conns[i].ProcessName));
                break;
            }
        }
    }

    /* Resolve FQDNs for each unique connection */
    for (DWORD i = 0; i < connCount; i++) {
        netconnections_ResolveFqdn(conns[i].SrcIp, dnsCache, &dnsCacheCount,
                                conns[i].SrcFqdn, sizeof(conns[i].SrcFqdn));
        netconnections_ResolveFqdn(conns[i].DstIp, dnsCache, &dnsCacheCount,
                                conns[i].DstFqdn, sizeof(conns[i].DstFqdn));
    }

    /* Header */
    clog_ArenaAppend(&scratch, "[net-connections]");
    clog_ArenaAppend(&scratch,
                     "\n%-19s  %-5s  %-s  %-s  %-*s  %-s  %-s  %-*s  %-4s  %-5s  %-20s",
                     "datetime", "proto",
                     "src-fqdn",
                     "src-ip",
                     NETCONNECTIONS_COL_PORT, "sport",
                     "dst-fqdn",
                     "dst-ip",
                     NETCONNECTIONS_COL_PORT, "dport",
                     "pkts", "pid", "process");
    clog_ArenaAppend(&scratch,
                     "\n%-19s  %-5s  %-s  %-s  %-*.*s  %-s  %-s  %-*.*s  %-4s  %-5s  %-20s",
                     "-------------------", "-----",
                     "--------",
                     "------",
                     NETCONNECTIONS_COL_PORT, NETCONNECTIONS_COL_PORT, "-----",
                     "--------",
                     "------",
                     NETCONNECTIONS_COL_PORT, NETCONNECTIONS_COL_PORT, "-----",
                     "----", "-----", "--------------------");

    /* Data rows */
    for (DWORD i = 0; i < connCount; i++) {
        CHAR srcPort[8], dstPort[8];
        snprintf(srcPort, sizeof(srcPort), conns[i].SrcPort ? "%lu" : "-", conns[i].SrcPort);
        snprintf(dstPort, sizeof(dstPort), conns[i].DstPort ? "%lu" : "-", conns[i].DstPort);

        CHAR pidStr[12];
        if (conns[i].Pid > 0)
            snprintf(pidStr, sizeof(pidStr), "%lu", conns[i].Pid);
        else
            snprintf(pidStr, sizeof(pidStr), "-");

        CHAR procStr[24];
        clog_utils_ClampString(
            conns[i].ProcessName[0] ? conns[i].ProcessName : "-", procStr, sizeof(procStr));

        clog_ArenaAppend(&scratch,
                         "\n%-19.19s  %-5.5s  %s  %s  %-*s  %s  %s  %-*s  %-4lu  %-5s  %-20s",
                         conns[i].Time,
                         conns[i].Proto,
                         conns[i].SrcFqdn,
                         conns[i].SrcIp,
                         NETCONNECTIONS_COL_PORT, srcPort,
                         conns[i].DstFqdn,
                         conns[i].DstIp,
                         NETCONNECTIONS_COL_PORT, dstPort,
                         conns[i].Count, pidStr, procStr);
    }
    clog_ArenaAppend(&scratch, "\n");

    free(conns);
    free(dnsCache);
}

#ifdef STANDALONE
int main(void) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    clog_ArenaState *st = clog_ArenaMake(0x200000); /* 2 MB */
    clog_net_connections(st->Memory);
    printf("%s", st->Start);
    clog_ArenaFreeAll(st);

    WSACleanup();
    return 0;
}
#endif
