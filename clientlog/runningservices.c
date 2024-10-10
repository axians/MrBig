#include "clientlog.h"
#include <winsvc.h>

LPTSTR runningservices_PrettyServiceStatus(DWORD state) {
    switch (state) {
    case SERVICE_CONTINUE_PENDING:
        return "Unpausing";
    case SERVICE_PAUSE_PENDING:
        return "Pausing";
    case SERVICE_START_PENDING:
        return "Starting";
    case SERVICE_STOP_PENDING:
        return "Stopping";
    case SERVICE_PAUSED:
        return "Paused";
    case SERVICE_RUNNING:
        return "Running";
    case SERVICE_STOPPED:
        return "Stopped";
    default:
        return "Unknown";
    }
}

void clog_runningservices(clog_Arena scratch) {
    SC_HANDLE hServiceManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
    clog_Defer(&scratch, hServiceManager, RETURN_INT, &CloseServiceHandle);

    BYTE *servicesBuffer = NULL;
    DWORD servicesBufferSize = 0;
    DWORD servicesBytesNeeded = 0;
    DWORD servicesNumReturned = 0;
    DWORD servicesResumeHandle = 0;

    EnumServicesStatusEx(hServiceManager, SC_ENUM_PROCESS_INFO, /*SERVICE_DRIVER |*/ SERVICE_WIN32, SERVICE_ACTIVE, NULL, 0, &servicesBytesNeeded, &servicesNumReturned, &servicesResumeHandle, NULL);
    servicesBufferSize = servicesBytesNeeded + 3 * sizeof(ENUM_SERVICE_STATUS_PROCESS);
    servicesBuffer = clog_ArenaAlloc(&scratch, BYTE, servicesBufferSize);
    BOOL servicesSuccessful = EnumServicesStatusEx(hServiceManager, SC_ENUM_PROCESS_INFO, /*SERVICE_DRIVER |*/ SERVICE_WIN32, SERVICE_ACTIVE, servicesBuffer, servicesBufferSize, &servicesBytesNeeded, &servicesNumReturned, &servicesResumeHandle, NULL);

    clog_ArenaAppend(&scratch, "[runningservices]");
    clog_ArenaAppend(&scratch, "\n%6s \t%-23s\t%-63s\t%s", "PID", "SERVICE", "DISPLAY NAME", "STATUS");
    if (!servicesSuccessful) {
        clog_ArenaAppend(&scratch, "(Unable to get services, error code %#010lx)", GetLastError());
    } else {
        LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)servicesBuffer;
        for (DWORD i = 0; i < servicesNumReturned; i++) {
            ENUM_SERVICE_STATUS_PROCESS service = services[i];
            clog_ArenaAppend(&scratch, "\n%6lu \t%-23s\t%-63s\t%s", service.ServiceStatusProcess.dwProcessId, service.lpServiceName, service.lpDisplayName, runningservices_PrettyServiceStatus(service.ServiceStatusProcess.dwCurrentState));
        }
    }

}

#ifdef STANDALONE
int main(int argc, TCHAR *argv[]) {
    clog_ArenaState *st = clog_ArenaMake(0x10000);
    clog_runningservices(st->Memory);
    clog_PopDeferAll(&st->Memory);
    printf("%s", st->Start);
}
#endif