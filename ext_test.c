#include "mrbig.h"

//#define DEBUGGING "jajamensan"

#ifdef DEBUGGING
char cfgdir[256];
int dirsep = '\\';

void mrlog(char *p)
{
	printf("mrlog: %s\n", p);
}
#endif

static void pickup_file(char *fn)
{
	char full_fn[1024], machname[261], testname[261];
	char *b, *s, *p;
	FILE *fp;
	size_t n;

	if (debug) mrlog("pickup_file(%s)", fn);

	if (get_option("no_ext", 0)) {
		/* no mrsend with clear status because we don't
		   know the names of the tests
		*/
		return;
	}

	snprintf(full_fn, sizeof(full_fn), "%s%c%s", pickupdir, dirsep, fn);

	p = strchr(fn, '.');
	if (p) {
		*p++ = 0;
		strncpy(machname, fn, sizeof(machname) - 1);
		strncpy(testname, p, sizeof(testname) - 1);
	} else {
		strncpy(machname, mrmachine, sizeof(machname));
		strncpy(testname, fn, sizeof(machname));
	}
	machname[sizeof(machname)-1] = 0;
	testname[sizeof(testname)-1] = 0;
	if (debug) {
		mrlog("pickup_file(%s)", fn);
		mrlog("Full path '%s'", full_fn);
		mrlog("machname = '%s'", machname);
		mrlog("testname = '%s'", testname);
	}
	fp = big_fopen("pickup_file", full_fn, "r");
	if (!fp) {
		mrlog("Can't pick up file");
		return;
	}

	b = big_malloc("pickup_file", report_size);
	s = big_malloc("pickup_file", report_size);
	n = fread(b, 1, report_size-1, fp);
	big_fclose("pickup_file", fp);
	remove(full_fn);
	b[n] = 0;
	no_return(b);

	p = strchr(b, '\n');

	if (p == NULL) {
		mrlog("No color in pickup file");
		goto Exit;
	}

	*p++ = 0;

	snprintf(s, report_size, "%s\n\n%s\n", now, p);

	mrsend(machname, testname, b, s);

Exit:
	big_free("pickup_file", b);
	big_free("pickup_file", s);
}

static void pickup(void)
{
	char pattern[1024];
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	pattern[0] = '\0';
	snprcat(pattern, sizeof pattern, "%s%c*", pickupdir, dirsep);

	if (debug) {
		mrlog("pickup()");
		mrlog("picking up from '%s'", pattern);
	}

	hFind = FindFirstFile(pattern, &FindFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		mrlog("Invalid pickup directory");
		return;
	}

	do {
		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			pickup_file(FindFileData.cFileName);
	} while (FindNextFile(hFind, &FindFileData));

	FindClose(hFind);
}


int contains_case_insensitive(const char *str, const char *substr) {
	/* Defensive checks to avoid underflow and NULL derefs which can cause
	   out-of-bounds reads and a segfault. */
	if (str == NULL || substr == NULL) return 0;
	size_t len_str = strlen(str);
	size_t len_sub = strlen(substr);

	if (len_sub == 0) return 1; // empty substring always matches
	if (len_str < len_sub) return 0; // can't contain a longer substring

	/* Use i + len_sub <= len_str as the loop condition to avoid subtracting
	   unsigned values (which would underflow if len_str < len_sub). */
	for (size_t i = 0; i + len_sub <= len_str; i++) {
		size_t j;
		for (j = 0; j < len_sub; j++) {
			if (tolower((unsigned char)str[i + j]) != tolower((unsigned char)substr[j])) {
				break;
			}
		}
		if (j == len_sub) return 1; // match found
	}
	return 0; // no match
}


const char* get_basepath(const char *path, char *out, size_t outlen) {
    if (!path || !out || outlen == 0) return NULL;

    const char *p_back = strrchr(path, '\\');
    const char *p_slash = strrchr(path, '/');
    const char *p = p_back > p_slash ? p_back : p_slash; // the last separator

    if (!p) {
        /* no directory component */
        if (outlen < 2) return NULL;
        out[0] = '\0';
        return out;
    }

    size_t len = (size_t)(p - path); // number of chars before separator
    if (len >= outlen) return NULL; // insufficient buffer

    memcpy(out, path, len);
    out[len] = '\0';
    return out;
}

int is_allowed_ext(const char *cmd)
{
	const char* ext = strrchr(cmd, '.');
	if (ext == NULL) return 0;

	if (strlen(cmd) > 128) return 0;

	/* Extract basepath into a buffer (no filename). */
	char basepath[1024];
	if (get_basepath(cmd, basepath, sizeof(basepath)) == NULL) return 0;

	if (debug) mrlog("is_allowed_ext: ext='%s', basepath='%s'\n", ext, basepath);
	// list of strings with allowed extensions
	const char* allowed_exts[] = {".bat", ".cmd"};

	// list of disallowed folder names

	const char* disallowed_folder[] = {"C:\\program files", "C:\\Program Data", "C:\\ProgramData", "C:\\Temp", "C:\\Tmp", "C:\\Windows", "C:\\Users"};
	
	int valid_ext = 0;
	for (int i = 0; i < sizeof(allowed_exts)/sizeof(allowed_exts[0]); i++) {
		if (_stricmp(ext, allowed_exts[i]) == 0) {
			valid_ext = 1;
			break;
		}
	}
	if (!valid_ext) return 0;
	for (int i = 0; i < sizeof(disallowed_folder)/sizeof(disallowed_folder[0]); i++) {
		if (contains_case_insensitive(basepath, disallowed_folder[i])) {
			return 0;
		}
	}
	return 1;
}

void ext_tests(int is_filter_enabled)
{
	char cfgfile[1024], cmd[1024], *p;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD n;
	int i;

	if (debug > 1) mrlog("ext_tests()");

	cfgfile[0] = '\0';
	snprcat(cfgfile, sizeof cfgfile, "%s%c%s", cfgdir, dirsep, "ext.cfg");
	read_cfg("ext", cfgfile);

	for (i = 0; get_cfg("ext", cmd, sizeof cmd, i); i++) {
		p = strchr(cmd, '\n');
		if (p) *p = '\0';
		if (cmd[0] == '#' || cmd[0] == '\0') continue;
		if (debug) mrlog("Ext test: %s", cmd);
		if (is_filter_enabled && !is_allowed_ext(cmd)) {
			if (debug) mrlog("Skipping disallowed ext test: %s", cmd);
			continue;
		}
		ZeroMemory(&si, sizeof si);
		ZeroMemory(&pi, sizeof pi);
		if (CreateProcess(NULL, cmd, NULL, NULL, FALSE,
				CREATE_NO_WINDOW|DETACHED_PROCESS,
				NULL, NULL, &si, &pi)) {
			/* Wait no more than two minutes */
			n = WaitForSingleObject(pi.hProcess, 120*1000);
			if (debug) mrlog("WaitForSingleObject returns %d", n);
			if (n == WAIT_TIMEOUT) {
				TerminateProcess(pi.hProcess, EXIT_FAILURE);
				mrlog("Terminating process");
				mrlog(cmd);
			}
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		} else {
			mrlog("CreateProcess failed");
		}
	}
	pickup();
}

