
# Used for Standalone versions or clientlog.exe
EXTRA_CFLAGS =

ifeq ($(DEV),1)
# Dev/Beta: 1.2.3.4-betaYYMMDDHHMM+HASH[-dirty]
	GIT_HASH?=$(shell git rev-parse --short HEAD)
	GIT_DIRTY?=$(shell git diff --quiet || echo -dirty)
	VERSION?=dev+$(GIT_HASH)$(GIT_DIRTY)
	CFLAGS=-Wall -g -ggdb -DDEBUG -O -DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
else
# Release: 1.2.3.4
	CFLAGS = -Wall -Werror -O2 -DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
endif

ODIR = .
_OBJ = applications.o bios.o certificates.o clientversion.o clock.o date.o domain.o diskinfo.o eventlog.o ipconfig.o kbs.o osversion.o processes.o reboots.o runningservices.o tcpconnections.o who.o winmemory.o winports.o winroute.o winuptime.o
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
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $<

clientlog.o: clientlog.c clientlog.h $(OBJ) $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $< 

clientlog.exe: EXTRA_CFLAGS = -DCLIENTLOGEXE
clientlog.exe: clientlog.o $(OBJ) $(ODIR)/utils.o $(ODIR)/arena.o 
	$(CC) $(CFLAGS) -o $@ $^  -lcrypt32 -lwevtapi -lpdh -lwtsapi32 -lws2_32 -liphlpapi -lole32 -lnetapi32 -lsecur32 -loleaut32

standalone:
	$(MAKE) .clean
	$(MAKE) DEV=1 PACKAGE=$(TARGET).exe $(TARGET) EXTRA_CFLAGS="-DSTANDALONE"

applications: $(ODIR)/applications.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

certificates: $(ODIR)/certificates.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lcrypt32

bios: $(ODIR)/bios.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

clientversion: $(ODIR)/clientversion.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

clock: $(ODIR)/clock.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

date: $(ODIR)/date.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

domain: $(ODIR)/domain.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lnetapi32 -lsecur32

diskinfo: $(ODIR)/diskinfo.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

eventlog: $(ODIR)/eventlog.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lwevtapi

ipconfig: $(ODIR)/ipconfig.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

kbs: $(ODIR)/kbs.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lole32 -loleaut32

osversion: $(ODIR)/osversion.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS)  -o $@ $^

processes:  $(ODIR)/processes.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lpdh

reboots: $(ODIR)/reboots.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

runningservices: $(ODIR)/runningservices.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^
 
tcpconnections: $(ODIR)/tcpconnections.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lws2_32 -liphlpapi

who: $(ODIR)/who.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lwtsapi32

winmemory: $(ODIR)/winmemory.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -lpdh

winports: $(ODIR)/winports.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^  -lws2_32  -liphlpapi
	
winroute: $(ODIR)/winroute.o $(ODIR)/utils.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

winuptime: $(ODIR)/winuptime.o $(ODIR)/arena.o
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^  -lpdh

dev: 
	$(MAKE) DEV=1 exe


.PHONY: clean
clean:
	$(MAKE) -C build_x64 .clean
	$(MAKE) -C build_x86 .clean

.clean:
	find . -type f \( -name '*.o' -or -name '*.exe' \)  -exec rm {} +