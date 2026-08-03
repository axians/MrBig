#include "mrbig.h"
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winevt.h>

#define NTP_SKEW_BUF        32768
#define NTP_SKEW_TEST       "ntp-skew"
#define NTP_MAX_SERVERS     16
#define NTP_SERVER_LEN      64
#define NTP_LAST_N_EVENTS   10
#define NTP_ALARMING_EVENTS -1 /* <0 means all listed events are informational only */

/* --- Helpers ------------------------------------------------------------ */

/*
 * Read NTP servers from the W32Time registry.
 * NT5DS: prefer active Source from w32tm /query /status;
 *        if source is local/free-running, parse configured NtpServer peers.
 *        if no peers are configured, fallback to one empty entry → local service.
 * NTP/AllSync: parses NtpServer value, strips ",flags".
 * Returns count (0 on error).
 */
static int get_ntp_servers(char servers[NTP_MAX_SERVERS][NTP_SERVER_LEN])
{
    /* For NT5DS, ask w32tm which upstream source is currently used. */
    char source[NTP_SERVER_LEN] = "";
    HKEY hKey;
    DWORD cbData;
    char ntpType[64] = "", raw[NTP_MAX_SERVERS * NTP_SERVER_LEN] = "";
    char *tok, *comma;
    int n = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;

    cbData = sizeof ntpType;
    RegQueryValueExA(hKey, "Type", NULL, NULL, (LPBYTE)ntpType, &cbData);
    cbData = sizeof raw;
    RegQueryValueExA(hKey, "NtpServer", NULL, NULL, (LPBYTE)raw, &cbData);
    RegCloseKey(hKey);

    if (!strcmp(ntpType, "NT5DS"))
    {
        FILE *fp;
        char line[512];

        fp = _popen("w32tm /query /status 2>&1", "r");
        if (fp)
        {
            while (fgets(line, sizeof line, fp))
            {
                char *p = line;
                while (*p == ' ' || *p == '\t')
                    p++;
                if (_strnicmp(p, "Source:", 7) == 0)
                {
                    char *src = p + 7;
                    char *end;
                    while (*src == ' ' || *src == '\t')
                        src++;
                    strlcpy(source, src, sizeof source);
                    end = source + strlen(source);
                    while (end > source && (end[-1] == '\r' || end[-1] == '\n' ||
                                            end[-1] == ' ' || end[-1] == '\t'))
                    {
                        *--end = '\0';
                    }
                    break;
                }
            }
            _pclose(fp);
        }

        if (source[0] &&
            _stricmp(source, "Local CMOS Clock") &&
            _stricmp(source, "Free-running System Clock"))
        {
            strlcpy(servers[0], source, NTP_SERVER_LEN);
            return 1;
        }

        /* Source is local/free-running: probe configured peers from NtpServer. */
        for (tok = strtok(raw, " \t"); tok && n < NTP_MAX_SERVERS; tok = strtok(NULL, " \t"))
        {
            if ((comma = strchr(tok, ',')))
                *comma = '\0';
            if (*tok)
                strlcpy(servers[n++], tok, NTP_SERVER_LEN);
        }

        if (n > 0)
            return n;

        /* Final fallback: local service probe. */
        servers[0][0] = '\0';
        return 1;
    }

    for (tok = strtok(raw, " \t"); tok && n < NTP_MAX_SERVERS; tok = strtok(NULL, " \t"))
    {
        if ((comma = strchr(tok, ',')))
            *comma = '\0';
        if (*tok)
            strlcpy(servers[n++], tok, NTP_SERVER_LEN);
    }
    return n;
}

/* Run w32tm /stripchart /computer:<server> /samples:1 /dataonly.
   Empty server → /computer: → local. Returns 1 + sets *offset on success. */
static int stripchart_offset(const char *server, double *offset)
{
    char cmd[512], line[512];
    FILE *fp;
    int found = 0;
    *offset = 0.0;

    snprintf(cmd, sizeof cmd,
             "w32tm /stripchart /computer:%.*s /samples:1 /dataonly 2>&1",
             NTP_SERVER_LEN - 1, server ? server : "");
    if (!(fp = _popen(cmd, "r")))
        return 0;

    while (fgets(line, sizeof line, fp))
    {
        if (line[2] == ':' && line[5] == ':')
        {                                 /* HH:MM:SS, ... */
            char *p = strstr(line, "o:"); /* prefer clock offset */
            if (!p)
            {
                p = strchr(line, ',');
                if (p)
                    p++;
            }
            else
                p += 2;
            while (p && *p == ' ')
                p++;
            if (p && sscanf(p, "%lf", offset) == 1)
                found = 1;
        }
    }
    _pclose(fp);
    return found;
}

/* Return 1 when Windows reports a local/free-running time source. */
static int is_free_running_clock(void)
{
    FILE *fp;
    char line[512];

    fp = _popen("w32tm /query /status 2>&1", "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof line, fp))
    {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (_strnicmp(p, "Source:", 7) == 0)
        {
            char *src = p + 7;
            char *end;
            while (*src == ' ' || *src == '\t')
                src++;
            end = src + strlen(src);
            while (end > src && (end[-1] == '\r' || end[-1] == '\n' ||
                                 end[-1] == ' ' || end[-1] == '\t'))
            {
                *--end = '\0';
            }
            _pclose(fp);
            return (!_stricmp(src, "Free-running System Clock") ||
                    !_stricmp(src, "Local CMOS Clock"));
        }
    }

    _pclose(fp);
    return 0;
}

/* Advance *p past the next YYYY-MM-DDTHH:MM:SS; return UTC time_t (0=none). */
static time_t next_iso8601(const char **p)
{
    for (; **p; (*p)++)
    {
        int Y, M, D, h, m, s;
        if ((*p)[4] == '-' && isdigit((unsigned char)(*p)[0]) &&
            sscanf(*p, "%4d-%2d-%2dT%2d:%2d:%2d", &Y, &M, &D, &h, &m, &s) == 6 &&
            Y > 2000 && M >= 1 && M <= 12)
        {
            struct tm t = {0};
            t.tm_year = Y - 1900;
            t.tm_mon = M - 1;
            t.tm_mday = D;
            t.tm_hour = h;
            t.tm_min = m;
            t.tm_sec = s;
            *p += 19;
            return _mkgmtime(&t);
        }
    }
    return 0;
}

static const char *color_worst(const char *a, const char *b)
{
    if (!strcmp(a, "red") || !strcmp(b, "red"))
        return "red";
    if (!strcmp(a, "yellow") || !strcmp(b, "yellow"))
        return "yellow";
    return "green";
}

static const char *color_for(double abs_val, int yellow_s, int red_s)
{
    if (abs_val >= red_s)
        return "red";
    if (abs_val >= yellow_s)
        return "yellow";
    return "green";
}

/* --- Event log time-jump table ------------------------------------------ */

static const char *append_time_jump_table(char *msg, int *pos, size_t msgsz,
                                          int yellow_s, int red_s)
{
    static const WCHAR QUERY[] =
        L"*[System[EventID=1 and Provider[@Name='Microsoft-Windows-Kernel-General']]]";
    const char *worst_color = "green";
    EVT_HANDLE hLog, events[NTP_LAST_N_EVENTS];
    DWORD n = 0, i;

    *pos += snprintf(msg + *pos, msgsz - *pos,
                     "<h3>Recent time-change events (System EventID 1, last %d)</h3>\n", NTP_LAST_N_EVENTS);
    if (NTP_ALARMING_EVENTS < 0)
    {
        *pos += snprintf(msg + *pos, msgsz - *pos,
                         "<span style=\"text-align:center;font-style:italic;color:grey;\">"
                         "Informational: all events listed below are non-alarming and do not affect alert status"
                         "</span>\n");
    }

    *pos += snprintf(msg + *pos, msgsz - *pos,
                     "<table border=\"1\" cellpadding=\"4\" cellspacing=\"0\">\n"
                     "<thead><tr><th>Status</th><th>RecordId</th><th>Event Time (UTC)</th>"
                     "<th>Old Time (UTC)</th><th>New Time (UTC)</th>"
                     "<th>Diff (s)</th><th>Reason</th></tr></thead>\n<tbody>\n");

    hLog = EvtQuery(NULL, L"System", QUERY,
                    EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hLog)
    {
        *pos += snprintf(msg + *pos, msgsz - *pos,
                         "<tr><td colspan=\"7\">(Could not query event log: %lu)</td></tr>\n",
                         GetLastError());
        goto done;
    }
    EvtNext(hLog, NTP_LAST_N_EVENTS, events, INFINITE, 0, &n);
    if (!n)
        *pos += snprintf(msg + *pos, msgsz - *pos,
                         "<tr><td colspan=\"7\">(No time-change events found)</td></tr>\n");

    for (i = 0; i < n && *pos < (int)msgsz - 512; i++)
    {
        char evtTime[32] = "-", msgtext[1024] = "-";
        time_t t_new = 0, t_old = 0;
        ULONGLONG recordId = 0;

        /* One EvtRenderContextSystem call gets both timestamp and provider name */
        EVT_HANDLE ctx = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
        DWORD need = 0, cnt = 0;
        BYTE buf[4096];
        EvtRender(ctx, events[i], EvtRenderEventValues, 0, NULL, &need, &cnt);
        if (need > 0 && need <= sizeof buf &&
            EvtRender(ctx, events[i], EvtRenderEventValues, need, buf, &need, &cnt))
        {
            EVT_VARIANT *v = (EVT_VARIANT *)buf;

            if (cnt > EvtSystemTimeCreated &&
                v[EvtSystemTimeCreated].Type != EvtVarTypeNull)
            {
                ULONGLONG ft = v[EvtSystemTimeCreated].FileTimeVal;
                SYSTEMTIME st;
                FileTimeToSystemTime((FILETIME *)&ft, &st);
                if (st.wYear > 9999 || st.wMonth > 12 || st.wDay > 31 || st.wHour > 23 ||
                    st.wMinute > 59 || st.wSecond > 59)
                    snprintf(evtTime, sizeof evtTime, "%04d-%02d-%02d %02d:%02d:%02d (invalid)",
                             1970, 01, 01,
                             00, 00, 00);
                else
                    snprintf(evtTime, sizeof evtTime, "%04d-%02d-%02d %02d:%02d:%02d",
                             st.wYear, st.wMonth, st.wDay,
                             st.wHour, st.wMinute, st.wSecond);
            }

            if (cnt > EvtSystemEventRecordId &&
                v[EvtSystemEventRecordId].Type != EvtVarTypeNull)
                recordId = v[EvtSystemEventRecordId].UInt64Val;

            if (cnt > EvtSystemProviderName &&
                v[EvtSystemProviderName].Type != EvtVarTypeNull)
            {
                LPCWSTR provW = v[EvtSystemProviderName].StringVal;
                EVT_HANDLE pm = EvtOpenPublisherMetadata(NULL, provW, NULL, 0, 0);
                DWORD fmn = 0;
                WCHAR dummy[1] = {L'\0'};
                EvtFormatMessage(pm, events[i], 0, 0, NULL, EvtFormatMessageEvent, 0, dummy, &fmn);
                if (fmn > 0 && fmn < 32 * 1024)
                {
                    WCHAR *wb = (WCHAR *)malloc(fmn * sizeof(WCHAR));
                    if (wb)
                    {
                        if (EvtFormatMessage(pm, events[i], 0, 0, NULL,
                                             EvtFormatMessageEvent, fmn, wb, &fmn))
                        {
                            /* Strip non-printable chars (bidi marks etc.) */
                            size_t wi = 0, ni = 0;
                            while (wb[wi] && ni < sizeof msgtext - 1)
                            {
                                wchar_t wc = wb[wi++];
                                if (wc >= 0x20 && wc <= 0x7E)
                                    msgtext[ni++] = (char)wc;
                            }
                            msgtext[ni] = '\0';
                            const char *p = msgtext;
                            t_new = next_iso8601(&p);
                            t_old = next_iso8601(&p);
                            char *cr = strstr(msgtext, "Change Reason:");
                            if (cr)
                            {
                                cr += 14;
                                while (*cr == ' ')
                                    cr++;
                                memmove(msgtext, cr, strlen(cr) + 1);
                            }
                            else
                                msgtext[0] = '\0';
                        }
                        free(wb);
                    }
                }
                if (pm)
                    EvtClose(pm);
            }
        }
        EvtClose(ctx);
        EvtClose(events[i]);

        char ts_new[32] = "-", ts_old[32] = "-";
        long diff = -1;
        if (t_new)
        {
            struct tm *g = gmtime(&t_new);
            strftime(ts_new, sizeof ts_new, "%Y-%m-%d %H:%M:%S", g);
        }
        if (t_old)
        {
            struct tm *g = gmtime(&t_old);
            strftime(ts_old, sizeof ts_old, "%Y-%m-%d %H:%M:%S", g);
        }
        if (t_new && t_old)
            diff = (long)labs((long)(t_new - t_old));

        const char *rc = diff < 0 ? "yellow" : color_for((double)diff, yellow_s, red_s);
        /* Only the most recent NTP_ALARMING_EVENTS events escalate the overall status */
        if (i < NTP_ALARMING_EVENTS && NTP_ALARMING_EVENTS > 0)
            worst_color = color_worst(worst_color, rc);

        *pos += snprintf(msg + *pos, msgsz - *pos,
                         "<tr><td>&%s</td>"
                         "<td>%llu</td>"
                         "<td style=\"white-space:nowrap\"><small>%s</small></td>"
                         "<td style=\"white-space:nowrap\"><small>%s</small></td>"
                         "<td style=\"white-space:nowrap\"><small>%s</small></td>"
                         "<td>%ld</td><td>%s</td></tr>\n",
                         rc, (unsigned long long)recordId, evtTime, ts_old, ts_new, diff, msgtext);

        /* Separator after the last alarming event */
        if (i == NTP_ALARMING_EVENTS - 1 && i < (int)n - 1)
            *pos += snprintf(msg + *pos, msgsz - *pos,
                             "<tr><td colspan=\"7\" style=\"text-align:center;font-style:italic;"
                             "color:grey;border-top:2px solid grey;\">"
                             "&#x2193; Historical only &mdash; events below do not affect the alert status"
                             "</td></tr>\n");
    }

done:
    if (hLog)
        EvtClose(hLog);
    *pos += snprintf(msg + *pos, msgsz - *pos, "</tbody></table>\n");
    return worst_color;
}

/* --- Main test ---------------------------------------------------------- */

void ntp_skew(void)
{
    char servers[NTP_MAX_SERVERS][NTP_SERVER_LEN];
    double offsets[NTP_MAX_SERVERS];
    int ok[NTP_MAX_SERVERS], nservers, i, worst_idx;
    int free_running;
    double worst_abs;
    char urlhost[256], msg[NTP_SKEW_BUF], *p;
    const char *color;
    int msgpos;

    if (debug > 1)
        mrlog("ntp_skew()");

    if (get_option("no_ntp_skew", 0))
    {
        mrsend(mrmachine, NTP_SKEW_TEST, "clear", "option no_ntp_skew\n");
        return;
    }

    strlcpy(urlhost, mrmachine, sizeof urlhost);
    for (p = urlhost; *p; p++)
        if (*p == ',')
            *p = '.';
    free_running = is_free_running_clock();

    nservers = get_ntp_servers(servers);
    if (!nservers)
    {
        mrsend(mrmachine, NTP_SKEW_TEST, "yellow",
               "Could not read NTP servers from registry.\n");
        return;
    }

    worst_abs = -1.0;
    worst_idx = -1;
    for (i = 0; i < nservers; i++)
    {
        ok[i] = stripchart_offset(servers[i], &offsets[i]);
        if (ok[i] && fabs(offsets[i]) > worst_abs)
        {
            worst_abs = fabs(offsets[i]);
            worst_idx = i;
        }
    }

    if (worst_idx < 0)
    {
        int n = snprintf(msg, sizeof msg, "%s\n\nNo NTP servers responded.\n", now);
        if (n < 0)
            msgpos = 0;
        else if ((size_t)n >= sizeof msg)
            msgpos = sizeof msg - 1;
        else
            msgpos = (size_t)n;

        for (i = 0; i < nservers && msgpos < sizeof msg - 1; i++)
        {
            size_t rem = sizeof msg - msgpos;
            n = snprintf(msg + msgpos, rem,
                         "  %s\n", servers[i][0] ? servers[i] : "(local)");
            if (n < 0)
                break;
            if ((size_t)n >= rem)
            {
                msgpos = sizeof msg - 1;
                break;
            }
            msgpos += (size_t)n;
        }
        mrsend(mrmachine, NTP_SKEW_TEST, "yellow", msg);
        return;
    }

    color = color_for(worst_abs, ntpskewyellow, ntpskewred);

    const char *worst_name = servers[worst_idx][0] ? servers[worst_idx] : "(local)";
    msgpos = snprintf(msg, sizeof msg,
                      "%s\n\n"
                      "<center>\n"
                      "Worst offset: %+.7fs  (%s)<br>\n"
                      "Thresholds  : yellow>=%ds  red>=%ds<br>\n",
                      now, offsets[worst_idx], worst_name,
                      ntpskewyellow, ntpskewred);

    if (free_running)
    {
        msgpos += snprintf(msg + msgpos, sizeof msg - msgpos,
                           "<span style=\"font-style:italic;color:gray\">"
                           "Note: Host time source is currently free-running/local clock;\n "
                           "the system is not actively synchronized, so offset against configured "
                           "NTP peers may be elevated"
                           "</span><br>\n");
    }
    msgpos += snprintf(msg + msgpos, sizeof msg - msgpos,
                       "<h2>Currently evaluating!</h2><br>Always &green for now, until we finetune the alert criteria\n");

    msgpos += snprintf(msg + msgpos, sizeof msg - msgpos,
                       "<table border=\"1\" cellpadding=\"4\" cellspacing=\"0\">\n"
                       "<thead><tr><th>Status</th><th>NTP Server</th><th>Offset</th></tr></thead>\n"
                       "<tbody>\n");

    for (i = 0; i < nservers && msgpos < (int)sizeof msg - 200; i++)
    {
        const char *display = servers[i][0] ? servers[i] : "(local)";
        const char *rc = ok[i] ? color_for(fabs(offsets[i]), ntpskewyellow, ntpskewred)
                               : "yellow";
        if (!ok[i])
            msgpos += snprintf(msg + msgpos, sizeof msg - msgpos,
                               "<tr><td>&%s</td><td>%s</td><td>(no response)</td></tr>\n",
                               rc, display);
        else
            msgpos += snprintf(msg + msgpos, sizeof msg - msgpos,
                               "<tr><td>&%s</td><td>%s</td><td>%+.7fs%s</td></tr>\n",
                               rc, display, offsets[i],
                               i == worst_idx ? " &lt;-- worst" : "");
    }
    msgpos += snprintf(msg + msgpos, sizeof msg - msgpos, "</tbody></table>\n</center>\n");

    color = color_worst(color,
                        append_time_jump_table(msg, &msgpos, sizeof msg,
                                               ntpskewyellow, ntpskewred));

    snprintf(msg + msgpos, sizeof msg - msgpos,
             "\n<h3>Clientlog [clock]</h3>\n"
             "\n<a href=\"/xymon-cgi/svcstatus.sh?CLIENT=%s&amp;SECTION=clock\">fallback link to clientlog [clock]</a>\n"
             "<center><pre>"
             "<iframe src=\"/xymon-cgi/svcstatus.sh?CLIENT=%s&amp;SECTION=clock\""
             " width=\"100%%\" height=\"600\" style=\"border:1px solid #ccc;\"></iframe>"
             "</pre></center>\n",
             urlhost, urlhost);

    // for now always green
    mrsend(mrmachine, NTP_SKEW_TEST, "green", msg);
#if 0 // actual send
    mrsend(mrmachine, NTP_SKEW_TEST, (char *)color, msg);
#endif
}
