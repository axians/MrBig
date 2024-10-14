#include "mrbig.h"
#include <iphlpapi.h>

/* We need to link with Iphlpapi.lib in Makefile. 
   This file also needs Ws2_32.lib, but that is a requirement for other files too */

#define MAX_PORT 0xFFFF

DWORD GetTcpPortStatistics(ULONG af, LPTSTR output) {
    PMIB_TCPTABLE_OWNER_PID tcp;
    DWORD status;
    DWORD size = 0;

    size = sizeof(MIB_TCPTABLE_OWNER_PID);
    tcp = (MIB_TCPTABLE_OWNER_PID *)big_malloc("tcp table", size);

    // Verify that we have enough memory allocated
    status = GetExtendedTcpTable(tcp, &size, TRUE, af, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        big_free("tcp table", tcp);
        tcp = (MIB_TCPTABLE_OWNER_PID *)big_malloc("tcp table", size);
        status = GetExtendedTcpTable(tcp, &size, TRUE, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (status != NO_ERROR) {
            if (debug) mrlog("GetTcpPortStatistics: Error calling GetExtendedTcpTable, error code %s",
                             status == ERROR_INSUFFICIENT_BUFFER ? "ERROR_INSUFFICIENT_BUFFER" : 
                             status == ERROR_INVALID_PARAMETER ? "ERROR_INVALID_PARAMETER" :
                             /*otherwise:*/ "unknown");
            big_free("tcp table", tcp);
            return 1;
        }
    }

    DWORD numEntries = tcp->dwNumEntries;
    big_free("tcp table", tcp);

    LPCTSTR ipVersion = af == AF_INET ? "IPv4" : "IPv6";
    DOUBLE percentPortsBusy = 100 * ((DOUBLE)numEntries) / ((DOUBLE)MAX_PORT);
    return sprintf(output, "%10s    %8s    %10lu    %12.2lf\n",
                   ipVersion, "TCP", numEntries, percentPortsBusy);
}

DWORD GetUdpPortStatistics(ULONG af, LPTSTR output) {
    PMIB_UDPTABLE_OWNER_PID udp;
    DWORD status;
    DWORD size = 0;

    size = sizeof(MIB_UDPTABLE_OWNER_PID);
    udp = (MIB_UDPTABLE_OWNER_PID *)big_malloc("udp table", size);

    // Verify that we have enough memory allocated
    status = GetExtendedUdpTable(udp, &size, TRUE, af, UDP_TABLE_OWNER_PID, 0);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        big_free("udp table", udp);
        udp = (MIB_UDPTABLE_OWNER_PID *)big_malloc("udp table", size);
        status = GetExtendedUdpTable(udp, &size, TRUE, af, UDP_TABLE_OWNER_PID, 0);
        if (status != NO_ERROR) {
            if (debug) mrlog("GetUdpPortStatistics: Error calling GetExtendedUdpTable, error code %s",
                             status == ERROR_INSUFFICIENT_BUFFER ? "ERROR_INSUFFICIENT_BUFFER" : 
                             status == ERROR_INVALID_PARAMETER ? "ERROR_INVALID_PARAMETER" :
                             /*otherwise:*/ "unknown");
            big_free("udp table", udp);
            return 1;
        }
    }

    DWORD numEntries = udp->dwNumEntries;
    big_free("udp table", udp);

    LPCTSTR ipVersion = af == AF_INET ? "IPv4" : "IPv6";
    DOUBLE percentPortsBusy = 100 * ((DOUBLE)numEntries) / ((DOUBLE)MAX_PORT);
    return sprintf(output, "%10s    %8s    %10lu    %12.2lf\n",
                   ipVersion, "UDP", numEntries, percentPortsBusy);
}

void port_usage(char *output) {
    // output fits comfortably in 255 characters at the time of writing
    PCHAR outputCurr = output;
    outputCurr += sprintf(output, "IP\tProto\tIn use\tStatic\tDynamic\tDynamic %%\n");
    outputCurr += GetTcpPortStatistics(AF_INET, outputCurr);
    outputCurr += GetUdpPortStatistics(AF_INET, outputCurr);
    outputCurr += GetTcpPortStatistics(AF_INET6, outputCurr);
    outputCurr += GetUdpPortStatistics(AF_INET6, outputCurr);
}