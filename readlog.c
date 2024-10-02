#include "mrbig.h"

static char **get_args(EVENTLOGRECORD *pBuf)
{
	char *cp;
	WORD arg_count;
	char **args = NULL;

	if (pBuf->NumStrings == 0) return NULL;

	args = big_malloc("get_args", sizeof(char *) * pBuf->NumStrings);
	cp = (char *)pBuf + (pBuf->StringOffset);

	for (arg_count=0; arg_count<pBuf->NumStrings; arg_count++) {
		args[arg_count] = cp;
		cp += strlen(cp) + 1;
	}
	return args;
}

static BOOL get_module_from_source(char *log,
	char *source_name, char *entry_name, 
	char *expanded_name)
{
	DWORD lResult;
	DWORD module_name_size;
	char module_name[1024];
	HKEY hAppKey = NULL;
	HKEY hSourceKey = NULL;
	BOOL bReturn = FALSE;
	char key[1024];

	key[0] = '\0';
	snprcat(key, sizeof key,
		"SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s", log);

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hAppKey);

	if (lResult != ERROR_SUCCESS) {
		if (debug) mrlog("get_module_from_source: registry can not open.");
		goto Exit;
	}

	lResult = RegOpenKeyEx(hAppKey, source_name, 0, KEY_READ, &hSourceKey);

	if (lResult != ERROR_SUCCESS) {
		if (debug) mrlog("get_module_from_source: can't RegOpenKeyEx");
		goto Exit;
	}

	module_name_size = sizeof module_name - 1;

	lResult = RegQueryValueEx(hSourceKey, "EventMessageFile",
	    NULL, NULL, (BYTE*)module_name, &module_name_size);
		
	if (lResult == ERROR_FILE_NOT_FOUND) {
		// Reg key doesn't exist, let's try the other way!
		char guid[1024];
		DWORD guid_size;
		memset(guid, 0, sizeof guid);
		if (debug) mrlog("get_module_from_source: ERROR_FILE_NOT_FOUND. Looking for DLL another way.");
		if (debug) mrlog("Looking for ProviderGuid");
		lResult = RegQueryValueEx(hSourceKey, "ProviderGuid", NULL, NULL, (BYTE*)guid, &guid_size);
		if (lResult != ERROR_SUCCESS) {
			if (debug) mrlog("get_module_from_source: Alternate method failed. Giving up.");
			goto Exit;
		}
		if (debug) mrlog("ProviderGuid: %s", guid);
		HKEY hPublisherKey = NULL;
		char publisherKey[1024];
		snprcat(publisherKey, sizeof publisherKey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\%s", guid);
		if (debug) mrlog("PublisherKey: %s", publisherKey);
		lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, publisherKey, 0, KEY_READ, &hPublisherKey);
		if (lResult != ERROR_SUCCESS) {
			if (debug) mrlog("get_module_from_source: Guid missing from registry. Giving up.");
			goto Exit;
		}
		lResult = RegQueryValueEx(hPublisherKey, "MessageFilename", NULL, NULL, (BYTE*)module_name, &module_name_size);
		if (lResult != ERROR_SUCCESS) {
			if (debug) mrlog("get_module_from_source: RegQueryvValueEx failed on alternate method key.");
			goto Exit;
		}
	}
	else if (lResult != ERROR_SUCCESS) {
		if (debug) mrlog("get_module_from_source: can't RegQueryValueEx");
		goto Exit;
	}

	/* RegQueryValueEx doesn't necessarily null-terminate */
	module_name[sizeof module_name - 1] = '\0';

	ExpandEnvironmentStrings(module_name, expanded_name, sizeof module_name - 1);

	bReturn = ERROR_SUCCESS;

Exit:
	if (hSourceKey != NULL) RegCloseKey(hSourceKey);
	if (hAppKey != NULL) RegCloseKey(hAppKey);

	return bReturn;
}

static BOOL disp_message(char *log, char *source_name, char *entry_name,
	char **args, DWORD MessageId,
	char *msgbuf, size_t msgsize)
{
	BOOL bResult;
	BOOL bReturn = FALSE;
	HANDLE hSourceModule = NULL;
	char source_module_name[1000];
	char *pMessage = NULL;
	source_module_name[0] = '\0';

	if (debug) {
		mrlog("About to call get_module_from_source(%s, %s, %s, %p)",
			log, source_name, entry_name, source_module_name);
	}

	bResult = get_module_from_source(log,
			source_name, entry_name, source_module_name);

	if (debug) {
		mrlog("get_module_from_source returns %d", bResult);
	}

	if (bResult != ERROR_SUCCESS) {
		if (debug) mrlog("disp_message: get_module_from_source failed");
		goto Exit;
	}

	/* Sometimes source_module_name will come back as a list of libraries,
	   i.e. this.dll;that.dll;someother.dll. That makes LoadLibraryEx
	   fail and no messages can be formatted. This ugly hack removes all
	   but the first dll so at least that one is loaded.
	*/

	if (1) {
		char *p = strchr(source_module_name, ';');
		if (p) {
			if (debug) {
				mrlog("source_module_name (before cutting) = '%s'", source_module_name);
			}
			*p = '\0';
		}
	}

	if (debug) {
		mrlog("source_module_name = '%s'", source_module_name);
	}

	hSourceModule = LoadLibraryEx(source_module_name, NULL,
		DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);

	if (debug) {
		mrlog("LoadLibraryEx returns %d", hSourceModule);
	}

	if (hSourceModule == NULL) goto Exit;

	if (debug) {
		mrlog("About to call FormatMessage(%d, %d, %d, %d, %p, %d, %p)",
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ARGUMENT_ARRAY,
			hSourceModule,
			MessageId,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&pMessage,
			0,
			(va_list *)args);
	}

	DWORD messageLength = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_HMODULE |
		FORMAT_MESSAGE_ARGUMENT_ARRAY,
		hSourceModule,
		MessageId,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&pMessage,
		0,
		(va_list *)args);
	
	if (messageLength == 0) { // FormatMessage errored
		if (debug) mrlog("disp_message: FormatMessage failed with 0x%x", GetLastError());
	} else {
		if (debug) mrlog("disp_message: FormatMessage returned a message of length %u, maximum before truncation is %u", messageLength, msgsize);
		bReturn = TRUE;
	}

Exit:
	msgbuf[0] = '\0';
	if (pMessage != NULL) snprcat(msgbuf, msgsize, "%s", pMessage);
	else snprcat(msgbuf, msgsize, "(%d)\n", (int)MessageId);

	if (hSourceModule != NULL) FreeLibrary(hSourceModule);
	if (pMessage != NULL) LocalFree(pMessage);

	return bReturn;
}

#if 0	/* Doesn't work with W2K3 or XP SP2 */
struct event *read_log(char *log, int maxage)
{
	struct event *e = NULL, *p;
	DWORD BufSize;
	DWORD ReadBytes;
	DWORD NextSize;
	BOOL bResult;
	char *cp;
	char *pSourceName;
	char *pComputerName;
	HANDLE hEventLog = NULL;
	EVENTLOGRECORD *pBuf = NULL;
	char **args = NULL;
	char msgbuf[1024];

	hEventLog = OpenEventLog(NULL, log);

	if(hEventLog == NULL) {
		printf("event log can not open.\n");
		goto Exit;
	}

	for(;;) {
		BufSize = 1;
		pBuf = big_malloc("read_log (pBuf)", BufSize);

		bResult = ReadEventLog(
			hEventLog,
			EVENTLOG_BACKWARDS_READ |
			EVENTLOG_SEQUENTIAL_READ,
			0,
			pBuf,
			BufSize,
			&ReadBytes,
			&NextSize);

		if (!bResult && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			break;

		BufSize = NextSize;
		pBuf = big_realloc("read_log (pBuf)", pBuf, BufSize);

		bResult = ReadEventLog(
			hEventLog,
			EVENTLOG_BACKWARDS_READ |
			EVENTLOG_SEQUENTIAL_READ,
			0,
			pBuf,
			BufSize,
			&ReadBytes,
			&NextSize);

		if(!bResult) break;

		if (pBuf->TimeGenerated < maxage) {
			//printf("Too old\n");
			goto Next;
		}
		p = big_malloc("read_log (node)", sizeof *p);
		p->next = e;
		e = p;
		e->record = pBuf->RecordNumber;
		e->gtime = pBuf->TimeGenerated;
		e->wtime = pBuf->TimeWritten;
		e->id = pBuf->EventID;
		e->type = pBuf->EventType;

		cp = (char *)pBuf;
		cp += sizeof(EVENTLOGRECORD);

		pSourceName = cp;
		cp += strlen(cp)+1;

		pComputerName = cp;
		cp += strlen(cp)+1;

		e->source = big_strdup("read_log (source)", pSourceName);

		args = get_args(pBuf);

		disp_message(log, pSourceName, "EventMessageFile",
			args, pBuf->EventID, msgbuf, sizeof msgbuf);
		e->message = big_strdup("read_log (message)", msgbuf);

		big_free("read_log (args)", args);
		args = NULL;

	Next:
		big_free("read_log (pBuf)", pBuf);
		pBuf = NULL;
	}

Exit:
	big_free("read_log (pBuf)", pBuf);
	big_free("read_log (args)", args);
	if (hEventLog) CloseEventLog(hEventLog);

	return e;
}
#else	/* Should work for any version */
struct event *read_log(char *log, int maxage, int fast)
{
	struct event *e = NULL, *p;
	DWORD BufSize = 64*1024;	/* works for NT4 and up */
	DWORD ReadBytes;
	DWORD NextSize;
	char *cp;
	char *pSourceName;
	HANDLE hEventLog = NULL;
	EVENTLOGRECORD *pBuf, *pBuf0 = NULL;
	char **args = NULL;
	char msgbuf[1024];

	hEventLog = OpenEventLog(NULL, log);

	if(hEventLog == NULL) {
		mrlog("read_log: Event log '%s' can not open.", log);
		goto Exit;
	}

	pBuf0 = big_malloc("read_log (pBuf)", BufSize);
	pBuf = pBuf0;
	memset(pBuf, 0, BufSize);
	while (ReadEventLog(hEventLog,
			EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
			0,
			pBuf,
			BufSize,
			&ReadBytes,
			&NextSize)) {
		if (debug > 1) {
			mrlog("ReadEventLog returns ReadBytes = %ld",
				ReadBytes);
		}
		while (ReadBytes > 0) {
			if (debug > 2) mrlog("ReadBytes = %ld", ReadBytes);
			if (pBuf->TimeGenerated < maxage) {
				if (debug > 2) mrlog("Too old");
				goto Next;
			}
			p = big_malloc("read_log (node)", sizeof *p);
			p->next = e;
			e = p;
			e->record = pBuf->RecordNumber;
			e->gtime = pBuf->TimeGenerated;
			e->wtime = pBuf->TimeWritten;
			e->id = pBuf->EventID;
			e->type = pBuf->EventType;

			cp = (char *)pBuf;
			cp += sizeof(EVENTLOGRECORD);

			pSourceName = cp;
			cp += strlen(cp)+1;

			cp += strlen(cp)+1;

			e->source = big_strdup("read_log (source)", pSourceName);

			args = get_args(pBuf);

			memset(msgbuf, 0, sizeof msgbuf);
			disp_message(log, pSourceName, "EventMessageFile",
				args, pBuf->EventID, msgbuf, sizeof msgbuf);
			e->message = big_strdup("read_log (message)", msgbuf);

			big_free("read_log (args)", args);
			args = NULL;
		Next:
			ReadBytes -= pBuf->Length;
			pBuf = (EVENTLOGRECORD *)
				((LPBYTE)pBuf+pBuf->Length);
		}
		pBuf = pBuf0;
		memset(pBuf, 0, BufSize);

		if (fast) break;
	}

Exit:
	big_free("read_log (pBuf)", pBuf0);
	big_free("read_log (args)", args);
	if (hEventLog) CloseEventLog(hEventLog);

	return e;
}
#endif

void free_log(struct event *e)
{
	struct event *p;

	while (e) {
		p = e;
		e = p->next;
		big_free("free_log(source)", p->source);
		big_free("free_log(message)", p->message);
		big_free("free_log(node)", p);
	}
}

void print_log(struct event *e)
{
	if (e == NULL) {
		printf("No messages\n");
		return;
	}

	while (e) {
		printf("Record Number: %d\n", (int)e->record);
		printf("Time Generated: %s", ctime(&e->gtime));
		printf("Time Written: %s", ctime(&e->wtime));
		printf("Event ID: %lu\n", (DWORD)e->id);
		printf("Event Type: ");
		switch(e->type) {
		case EVENTLOG_SUCCESS:
			printf("Success\n");
			break;
		case EVENTLOG_ERROR_TYPE:
			printf("Error\n");
			break;
		case EVENTLOG_WARNING_TYPE:
			printf("Warning\n");
			break;
		case EVENTLOG_INFORMATION_TYPE:
			printf("Information\n");
			break;
		case EVENTLOG_AUDIT_SUCCESS:
			printf("Audit success\n");
			break;
		case EVENTLOG_AUDIT_FAILURE:
			printf("Audit failure\n");
			break;
		default:
			printf("Unknown\n");
			break;
		}
		printf("Source: %s\n", e->source);
		printf("Message: %s\n", e->message);
		printf("\n");
		e = e->next;
	}
}

#if 0
int main(int argc, char **argv)
{
	int maxage = 360000;	/* 100h is really old... */
	struct event *app, *sys, *sec;

	time_t now = time(NULL);

	app = read_log("Application", now-maxage, 0);
	sys = read_log("System", now-maxage, 0);
	sec = read_log("Security", now-maxage, 0);
	printf("Application\n\n");
	print_log(app);
	printf("\n\nSystem\n\n");
	print_log(sys);
	printf("\n\nSecurity\n\n");
	print_log(sec);
	free_log(app);
	free_log(sys);
	free_log(sec);
	return 0;
}
#endif
