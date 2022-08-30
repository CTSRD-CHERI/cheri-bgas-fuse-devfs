SRC = CHERI_BGAS_fuse_devfs.c
OUTPT = cheri-bgas-fuse-devfs

BLUEAXI4DIR = $(CURDIR)/BlueAXI4
BLUEUNIXBRIDGESDIR = $(BLUEAXI4DIR)/BlueUnixBridges

OBJDIR = obj

CFLAGS = -O3  -Wall -Wno-unused -D_FILE_OFFSET_BITS=64 -fPIC
FUSECFLAGS = $(CFLAGS) $(shell pkg-config fuse3 --cflags --libs)

all: $(OUTPT)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/BlueUnixBridges.o: $(BLUEUNIXBRIDGESDIR)/BlueUnixFifo.c $(BLUEUNIXBRIDGESDIR)/BlueUnixFifo.h $(OBJDIR)
	$(CC) $(CFLAGS) -I $(BLUEUNIXBRIDGESDIR) -c -o $@ $<

$(OBJDIR)/BlueAXI4UnixBridges.o: $(BLUEAXI4DIR)/BlueAXI4UnixBridges.c $(BLUEAXI4DIR)/BlueAXI4UnixBridges.h $(OBJDIR)
	$(CC) $(CFLAGS) -I $(BLUEAXI4DIR) -I $(BLUEUNIXBRIDGESDIR) -c -o $@ $<

$(OUTPT): $(SRC) $(OBJDIR)/BlueUnixBridges.o $(OBJDIR)/BlueAXI4UnixBridges.o
	$(CC) -L $(OBJDIR) -I $(CURDIR) -I $(BLUEAXI4DIR) -I $(BLUEUNIXBRIDGESDIR) -o $@ $^ $(FUSECFLAGS)

.PHONY: clean

clean:
	rm -f $(OUTPT)
	rm -rf $(OBJDIR)
