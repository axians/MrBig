#include "clientlog.h"
#include <iphlpapi.h>

/* We need to link with Iphlpapi.lib in Makefile.
   This file also needs Ws2_32.lib, but that is a requirement for other files too */

#define MAX_PORT 0xFFFF

typedef enum {
    TCP = 1,
    UDP,
} winports_Protocol;

typedef enum {
    IPv4 = 2,
    IPv6 = 23,
} winports_IpVersion;

typedef struct {
    ULONG IPVersion;
    winports_Protocol Proto;
    CHAR LocalAddress[64], RemoteAddress[64];
    DWORD State;
    DWORD PID;
} winports_Record;

CHAR *winports_PrettyIPv6(BYTE *b, DWORD port, CHAR *out) {
    UINT16 group[8];
    for (DWORD i = 0; i < 8; i++) {
        UINT16 b1 = b[15 - 2 * i];
        UINT16 b2 = b[14 - 2 * i];
        group[i] = ((UINT16)b1 << 8) + b2;
    }

    DWORD largestZeroClusterIx = 0;
    DWORD largestZeroClusterLen = 0;
    DWORD curr, len;
    for (DWORD i = 0; i < 8; i++) {
        if (group[i] == 0) {
            curr = i;
            len = 1;
            while (++i < 8 && group[i] == 0) {
                len++;
            }
            if (len > largestZeroClusterLen) {
                largestZeroClusterIx = curr;
                largestZeroClusterLen = len;
            }
        }
    }

    if (largestZeroClusterLen == 0) {
        largestZeroClusterIx = 8;
    }

    CHAR *currOut = out;
    currOut += sprintf(currOut, "[");
    for (DWORD i = 0; i < largestZeroClusterIx; i++) {
        currOut += sprintf(currOut, "%x", group[i]);
        if (i != largestZeroClusterIx - 1)
            currOut += sprintf(currOut, ":");
    }
    if (largestZeroClusterLen > 0) {
        currOut += sprintf(currOut, "::");
    }
    for (DWORD i = largestZeroClusterIx + largestZeroClusterLen; i < 8; i++) {
        currOut += sprintf(currOut, "%x", group[i]);
        if (i != 7)
            currOut += sprintf(currOut, ":");
    }
    currOut += sprintf(currOut, "]:%u", ntohs((u_short)port));
    return out;
}

LPCSTR winports_PrettyPortState(DWORD state, CHAR *out) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED:
        return "CLOSED";
    case MIB_TCP_STATE_LISTEN:
        return "LISTENING";
    case MIB_TCP_STATE_SYN_SENT:
        return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:
        return "SYN_RECEIVED";
    case MIB_TCP_STATE_ESTAB:
        return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:
        return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:
        return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:
        return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:
        return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:
        return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:
        return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:
        return "DELETE_TCB";
    default:
        return "(Unknown)";
    }
}

void *winports_GetConnectionTable(ULONG af, winports_Protocol proto, clog_Arena *a) {
    DWORD status = NO_ERROR, size = 0;
    void *result;
    switch (proto) {
    case TCP:
        status = GetExtendedTcpTable(NULL, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) return NULL;
        result = clog_ArenaAlloc(a, void, size);
        status = GetExtendedTcpTable(result, &size, TRUE, af, TCP_TABLE_OWNER_PID_ALL, 0);
        break;
    case UDP:
        status = GetExtendedUdpTable(NULL, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER) return NULL;
        result = clog_ArenaAlloc(a, void, size);
        status = GetExtendedUdpTable(result, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
        break;
    default:
        result = NULL;
        break;
    }
    if (status != NO_ERROR) {
        result = NULL;
    }
    return result;
}

BOOL equalipv6(UCHAR addr1[16], UCHAR addr2[16]) {
    for (DWORD i = 0; i < 16; i++) {
        if (addr1[i] != addr2[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

void winports_AppendConnections(void *connections, const ULONG af, const winports_Protocol proto, clog_Arena *a) {
    winports_Record r;
    r.Proto = proto;
    r.IPVersion = af;

    CHAR portStateBuf[16];
    struct in_addr ipAddress;
    DWORD numEntries = ((MIB_TCPTABLE_OWNER_PID *)connections)->dwNumEntries;
    for (DWORD i = 0; i < numEntries; i++) {
        DWORD range = 1;
        DWORD lastPort = 0;
        switch (af) {
        case IPv4:
            switch (proto) {
            case TCP:
                MIB_TCPROW_OWNER_PID *tcp4row = &((MIB_TCPTABLE_OWNER_PID *)connections)->table[i];
                while (i + range < numEntries &&
                       ((MIB_TCPTABLE_OWNER_PID *)connections)->table[i + range].dwLocalAddr == tcp4row->dwLocalAddr &&
                       ((MIB_TCPTABLE_OWNER_PID *)connections)->table[i + range].dwOwningPid == tcp4row->dwOwningPid) {
                    range++;
                }
                lastPort = ((MIB_TCPTABLE_OWNER_PID *)connections)->table[i + range - 1].dwLocalPort;
                ipAddress.S_un.S_addr = (u_long)tcp4row->dwLocalAddr;
                snprintf(r.LocalAddress, sizeof(r.LocalAddress), "%s:%u", inet_ntoa(ipAddress), ntohs(tcp4row->dwLocalPort));

                ipAddress.S_un.S_addr = (u_long)tcp4row->dwRemoteAddr;
                snprintf(r.RemoteAddress, sizeof(r.RemoteAddress), "%s:%u", inet_ntoa(ipAddress), ntohs(tcp4row->dwRemotePort));
                r.State = tcp4row->dwState;
                r.PID = tcp4row->dwOwningPid;
                break;
            case UDP:
                MIB_UDPROW_OWNER_PID *udp4row = &((MIB_UDPTABLE_OWNER_PID *)connections)->table[i];
                while (i + range < numEntries &&
                       ((MIB_UDPTABLE_OWNER_PID *)connections)->table[i + range].dwLocalAddr == udp4row->dwLocalAddr &&
                       ((MIB_UDPTABLE_OWNER_PID *)connections)->table[i + range].dwOwningPid == udp4row->dwOwningPid) {
                    range++;
                }
                lastPort = ((MIB_UDPTABLE_OWNER_PID *)connections)->table[i + range - 1].dwLocalPort;
                ipAddress.S_un.S_addr = (u_long)udp4row->dwLocalAddr;
                snprintf(r.LocalAddress, sizeof(r.LocalAddress), "%s:%u", inet_ntoa(ipAddress), ntohs(udp4row->dwLocalPort));
                memcpy(r.RemoteAddress, "*:*", 4); // same as netstat
                r.State = 99;
                r.PID = udp4row->dwOwningPid;
                break;
            default:
                break;
            }
            break;
        case IPv6:
            switch (proto) {
            case TCP:
                MIB_TCP6ROW_OWNER_PID *tcp6row = &((MIB_TCP6TABLE_OWNER_PID *)connections)->table[i];
                while (i + range < numEntries &&
                       ((MIB_TCP6TABLE_OWNER_PID *)connections)->table[i + range].dwOwningPid == tcp6row->dwOwningPid &&
                       equalipv6(((MIB_TCP6TABLE_OWNER_PID *)connections)->table[i + range].ucLocalAddr, tcp6row->ucLocalAddr)) {
                    range++;
                }
                lastPort = ((MIB_TCP6TABLE_OWNER_PID *)connections)->table[i + range - 1].dwLocalPort;
                winports_PrettyIPv6(tcp6row->ucLocalAddr, tcp6row->dwLocalPort, r.LocalAddress);
                winports_PrettyIPv6(tcp6row->ucRemoteAddr, tcp6row->dwRemotePort, r.RemoteAddress);
                r.State = tcp6row->dwState;
                r.PID = tcp6row->dwOwningPid;
                break;
            case UDP:
                MIB_UDP6ROW_OWNER_PID *udp6row = &((MIB_UDP6TABLE_OWNER_PID *)connections)->table[i];
                while (i + range < numEntries &&
                       ((MIB_TCP6TABLE_OWNER_PID *)connections)->table[i + range].dwOwningPid == udp6row->dwOwningPid &&
                       equalipv6(((MIB_UDP6TABLE_OWNER_PID *)connections)->table[i + range].ucLocalAddr, udp6row->ucLocalAddr)) {
                    range++;
                }
                lastPort = ((MIB_UDP6TABLE_OWNER_PID *)connections)->table[i + range - 1].dwLocalPort;
                winports_PrettyIPv6(udp6row->ucLocalAddr, udp6row->dwLocalPort, r.LocalAddress);
                memcpy(r.RemoteAddress, "*:*", 4); // same as netstat
                r.State = 99;
                r.PID = udp6row->dwOwningPid;
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }

        clog_ArenaAppend(a, "\n%-7s\t%-31s\t%-31s\t%-15s\t%7lu",
                         proto == TCP ? "TCP" : "UDP",
                         r.LocalAddress,
                         r.RemoteAddress,
                         proto == TCP ? winports_PrettyPortState(r.State, portStateBuf) : "",
                         r.PID);

        if (range > 1) {
            clog_ArenaAppend(a, "\n\t...the above IP and PID spans %lu additional ports, up to and including port %u", range - 1, ntohs(lastPort));
            i += range - 1;
        }
    }
}

void winports_AppendPortStatistics(ULONG af, winports_Protocol proto, DWORD numEntries, clog_Arena *a) {
    LPCTSTR ipVersion = af == IPv4 ? "IPv4" : "IPv6";
    LPCTSTR protocol = proto == TCP ? "TCP" : "UDP";

    DOUBLE percentPortsBusy = 100 * ((DOUBLE)numEntries) / ((DOUBLE)MAX_PORT);
    clog_ArenaAppend(a, "\n%-15s\t%-15s\t%15lu\t%13.2lf",
                     ipVersion, protocol, numEntries, percentPortsBusy);
}

void clog_winports(clog_Arena scratch) {
    MIB_TCPTABLE_OWNER_PID *tcpIpv4 = winports_GetConnectionTable(IPv4, TCP, &scratch);
    MIB_TCP6TABLE_OWNER_PID *tcpIpv6 = winports_GetConnectionTable(IPv6, TCP, &scratch);
    MIB_UDPTABLE_OWNER_PID *udpIpv4 = winports_GetConnectionTable(IPv4, UDP, &scratch);
    MIB_UDP6TABLE_OWNER_PID *udpIpv6 = winports_GetConnectionTable(IPv6, UDP, &scratch);

    clog_ArenaAppend(&scratch, "[winportsused]");
    clog_ArenaAppend(&scratch, "\n%-15s\t%-15s\t%15s\t%13s", "IP version", "Protocol", "Ports Used #", "Ports Used %");
    if (tcpIpv4 != NULL) winports_AppendPortStatistics(IPv4, TCP, tcpIpv4->dwNumEntries, &scratch);
    if (tcpIpv6 != NULL) winports_AppendPortStatistics(IPv6, TCP, tcpIpv6->dwNumEntries, &scratch);
    if (udpIpv4 != NULL) winports_AppendPortStatistics(IPv4, UDP, udpIpv4->dwNumEntries, &scratch);
    if (udpIpv6 != NULL) winports_AppendPortStatistics(IPv6, UDP, udpIpv6->dwNumEntries, &scratch);

    BOOL allErrored = tcpIpv4 == NULL && tcpIpv6 == NULL && udpIpv4 == NULL && udpIpv6 == NULL;
    BOOL anyErrored = tcpIpv4 == NULL || tcpIpv6 == NULL || udpIpv4 == NULL || udpIpv6 == NULL;
    if (allErrored)
        clog_ArenaAppend(&scratch, "\n(Unable to get networking statistics)");
    else if (anyErrored)
        clog_ArenaAppend(&scratch, "\n(Unable to get some of the networking statistics)");

    clog_ArenaAppend(&scratch, "\n[winports]");
    clog_ArenaAppend(&scratch, "\n%-7s\t%-31s\t%-31s\t%-15s\t%7s", "Proto.", "Local Address", "Foreign Address", "State", "PID");
    if (tcpIpv4 != NULL) winports_AppendConnections(tcpIpv4, IPv4, TCP, &scratch);
    if (tcpIpv6 != NULL) winports_AppendConnections(tcpIpv6, IPv6, TCP, &scratch);
    if (udpIpv4 != NULL) winports_AppendConnections(udpIpv4, IPv4, UDP, &scratch);
    if (udpIpv6 != NULL) winports_AppendConnections(udpIpv6, IPv6, UDP, &scratch);

    if (allErrored)
        clog_ArenaAppend(&scratch, "\n(Unable to get networking statistics)");
    else if (anyErrored)
        clog_ArenaAppend(&scratch, "\n(Unable to get some of the networking statistics)");
}

#ifdef STANDALONE
int main(int argc, CHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_winports(st->Memory);
    printf("%s", st->Start);
}
#endif