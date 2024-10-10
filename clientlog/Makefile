
# CFLAGS = -Wall -O -g -DDEBUG
CFLAGS = -Wall -O2
ODIR = .
_OBJ = applications.o certificates.o clock.o date.o diskinfo.o eventlog.o ipconfig.o osversion.o processes.o reboots.o runningservices.o who.o winmemory.o winports.o winroute.o winuptime.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

exe: x86.exe x64.exe

objectfile: x86.o x64.o

x86.exe x86.o: build_x86
	$(MAKE) -C $< clientlog$(suffix $@)

x64.exe x64.o: build_x64
	$(MAKE) -C $< clientlog$(suffix $@)

build_x86 build_x64:
	mkdir -p ./$@

$(ODIR)/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clientlog.o: clientlog.c $(OBJ) $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) -c -o $@ $< $(CFLAGS)

clientlog.exe: clientlog.o $(OBJ) $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^ -DCLIENTLOGEXE -lcrypt32 -lwevtapi -lpdh -lwtsapi32 -lws2_32 -liphlpapi -DCLIENTLOGEXE

applications: $(ODIR)/applications.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^ -DSTANDALONE

certificates: $(ODIR)/certificates.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt32

clock: $(ODIR)/clock.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

date: $(ODIR)/date.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

diskinfo: $(ODIR)/diskinfo.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

eventlog: $(ODIR)/eventlog.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^ -lWevtapi

ipconfig: $(ODIR)/ipconfig.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

osversion: $(ODIR)/osversion.o
	$(CC) $(CFLAGS) -o $@ $^

processes:  $(ODIR)/processes.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^ -lpdh

reboots: $(ODIR)/reboots.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

runningservices: $(ODIR)/runningservices.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

who: $(ODIR)/who.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^ -lWtsapi32

winmemory: $(ODIR)/winmemory.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

winports: $(ODIR)/winports.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^  -lWs2_32  -lIphlpapi
	
winroute: $(ODIR)/winroute.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) -o $@ $^

winuptime: $(ODIR)/uptime.o
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	$(MAKE) -C build_x64 .clean
	$(MAKE) -C build_x86 .clean

.clean:
	find . -type f \( -name '*.o' -or -name '*.exe' \)  -exec rm {} +