/*-
* SPDX-License-Identifier: BSD-2-Clause
*
* Copyright (c) 2022 Alexandre Joannou <aj443@cam.ac.uk>
* Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
* Copyright (c) 2022 Jon Woodruff <Jonathan.Woodruff@cl.cam.ac.uk>
*
* This material is based upon work supported by the DoD Information Analysis
* Center Program Management Office (DoD IAC PMO), sponsored by the Defense
* Technical Information Center (DTIC) under Contract No. FA807518D0004.  Any
* opinions, findings and conclusions or recommendations expressed in this
* material are those of the author(s) and do not necessarily reflect the views
* of the Air Force Installation Contracting Agency (AFICA).
*
* This work was supported by Innovate UK project 105694, "Digital Security
* by Design (DSbD) Technology Platform Prototype".
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*
* $FreeBSD$
*/

#define FUSE_USE_VERSION 35

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdbool.h>

#include <BlueUnixBridges.h>
#include <BlueAXI4UnixBridges.h>

// list helpers
////////////////////////////////////////////////////////////////////////////////
typedef struct node { void* payload; struct node* next; } node_t;
typedef node_t* list_t;
static void map_ (void (*f) (void*), list_t xs) {
  if (xs != NULL) { f (xs->payload); map_ (f, xs->next); }
}
static void* find_ (bool (*pred) (void*), const list_t xs) {
  if (xs == NULL) return NULL;
  else if (pred (xs->payload)) return xs->payload;
  else return find_ (pred, xs->next);
}
// H2F LW devices
////////////////////////////////////////////////////////////////////////////////
typedef struct h2f_lw_dev {
  const char* name;
  const uint32_t base_addr;
  const uint32_t range;
} h2f_lw_dev_t;
static const list_t h2f_lw_dev_list =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "debug_unit"
                                       , .base_addr = 0x00000000
                                       , .range     = 0x00001000 }
          , .next =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "irqs"
                                       , .base_addr = 0x00001000
                                       , .range     = 0x00001000 }
          , .next =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "misc"
                                       , .base_addr = 0x00002000
                                       , .range     = 0x00001000 }
          , .next =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "uart0"
                                       , .base_addr = 0x00003000
                                       , .range     = 0x00001000 }
          , .next =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "uart1"
                                       , .base_addr = 0x00004000
                                       , .range     = 0x00001000 }
          , .next =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "h2f_addr_ctrl"
                                       , .base_addr = 0x00005000
                                       , .range     = 0x00001000 }
          , .next =
&(node_t) { .payload = &(h2f_lw_dev_t) { .name      = "virtual_device"
                                       , .base_addr = 0x00008000
                                       , .range     = 0x00004000 }
          , .next = NULL }}}}}}};
static void h2f_lw_devs_map (void (*f) (h2f_lw_dev_t*)) {
  void g (void* dev) { f ((h2f_lw_dev_t*) dev); }
  map_ (g, h2f_lw_dev_list);
}
static const h2f_lw_dev_t* h2f_lw_devs_find (const char* path) {
  bool pred (void* dev)
    { return (strcmp (path+1, ((h2f_lw_dev_t*) dev)->name) == 0); }
  return (const h2f_lw_dev_t*) find_ (pred, h2f_lw_dev_list);
}
static void h2f_lw_devs_print () {
  void print_dev (h2f_lw_dev_t* dev) {
    printf ( "name: %15s, base_addr: 0x%08x, range: 0x%08x\n"
           , dev->name, dev->base_addr, dev->range );
  }
  h2f_lw_devs_map (print_dev);
}

// H2F_LW AXI4 port parameters
////////////////////////////////////////////////////////////////////////////////

#define H2F_LW_FOLDER "h2f_lw"

#ifndef H2F_LW_ID
#define H2F_LW_ID 0
#endif
#ifndef H2F_LW_ADDR
#define H2F_LW_ADDR 21
#endif
#ifndef H2F_LW_DATA
#define H2F_LW_DATA 32
#endif
#ifndef H2F_LW_AWUSER
#define H2F_LW_AWUSER 0
#endif
#ifndef H2F_LW_WUSER
#define H2F_LW_WUSER 0
#endif
#ifndef H2F_LW_BUSER
#define H2F_LW_BUSER 0
#endif
#ifndef H2F_LW_ARUSER
#define H2F_LW_ARUSER 0
#endif
#ifndef H2F_LW_RUSER
#define H2F_LW_RUSER 0
#endif

DEF_AXI4_API( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA
            , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER
            , H2F_LW_ARUSER, H2F_LW_RUSER )

#define _H2F_LW_( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA \
                , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER \
                , H2F_LW_ARUSER, H2F_LW_RUSER \
                , sym ) \
  AXI4_( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA \
       , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER \
       , H2F_LW_ARUSER, H2F_LW_RUSER \
       , sym )
#define H2F_LW_(sym) _H2F_LW_( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA \
                             , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER \
                             , H2F_LW_ARUSER, H2F_LW_RUSER \
                             , sym )

#define _H2F_LW_AW_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER, sym) \
  AXI4_AW_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER, sym)
#define H2F_LW_AW_(sym) _H2F_LW_AW_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER, sym)

#define _H2F_LW_W_(H2F_LW_DATA, H2F_LW_WUSER, sym) \
  AXI4_W_(H2F_LW_DATA, H2F_LW_WUSER, sym)
#define H2F_LW_W_(sym) _H2F_LW_W_(H2F_LW_DATA, H2F_LW_WUSER, sym)

#define _H2F_LW_B_(H2F_LW_ID, H2F_LW_BUSER, sym) \
  AXI4_B_(H2F_LW_ID, H2F_LW_BUSER, sym)
#define H2F_LW_B_(sym) _H2F_LW_B_(H2F_LW_ID, H2F_LW_BUSER, sym)

#define _H2F_LW_AR_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER, sym) \
  AXI4_AR_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER, sym)
#define H2F_LW_AR_(sym) _H2F_LW_AR_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER, sym)

#define _H2F_LW_R_(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER, sym) \
  AXI4_R_(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER, sym)
#define H2F_LW_R_(sym) _H2F_LW_R_(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER, sym)

////////////////////////////////////////////////////////////////////////////////

typedef struct {
  baub_port_fifo_desc_t* h2flw;
  baub_port_fifo_desc_t* h2f;
  baub_port_fifo_desc_t* f2h;
} sim_ports_t;

#define EXPOSE_SIMPORTS() ((sim_ports_t*) fuse_get_context()->private_data)

static void* _init (struct fuse_conn_info* conn, struct fuse_config* cfg) {
  printf ("cheri-bgas-fuse-devfs -- init\n");
  // private data initially set to path to simulator ports folder
  const char* portsPath = (char*) fuse_get_context()->private_data;
  size_t len = strlen (portsPath) + 1;
  // H2F LW interface
  /**/h2f_lw_devs_print ();
  char* h2flwPath = (char*) malloc (len + strlen ("/" H2F_LW_FOLDER));
  strcpy (h2flwPath, portsPath);
  strcat (h2flwPath, "/" H2F_LW_FOLDER);
  baub_port_fifo_desc_t* h2flwDesc = H2F_LW_(fifo_OpenAsSlave)(h2flwPath);
  sim_ports_t* simports = (sim_ports_t*) malloc (sizeof (sim_ports_t));
  simports->h2flw = h2flwDesc;
  // H2F interface TODO
  simports->h2f   = NULL;
  // F2H interface TODO
  simports->f2h   = NULL;
  // return simulator ports
  return (void*) simports;
}

static void _destroy (void* private_data) {
  printf ("cheri-bgas-fuse-devfs -- destroy\n");
  sim_ports_t* simports = EXPOSE_SIMPORTS();
  baub_fifo_Close (simports->h2flw);
  free (simports);
  //free (ctxt);
}

static int _getattr ( const char* path
                    , struct stat* st
                    , struct fuse_file_info* fi ) {
  printf ("cheri-bgas-fuse-devfs -- getattr\n");
  st->st_uid = getuid ();
  st->st_gid = getgid ();
  st->st_atime = time (NULL);
  st->st_mtime = time (NULL);
  sim_ports_t* simports = EXPOSE_SIMPORTS();
  if (strcmp (path, "/") == 0) {
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
  } else if (h2f_lw_devs_find (path) != NULL) {
    st->st_mode = S_IFREG | 0644;
    st->st_nlink = 1;
    st->st_size = 0;
  } else return -ENOENT;
  return 0;
}

static int _readdir ( const char* path
                    , void* entries
                    , fuse_fill_dir_t add_entry
                    , off_t offset
                    , struct fuse_file_info* fi
                    , enum fuse_readdir_flags flags ) {
  printf ("cheri-bgas-fuse-devfs -- readdir\n");
  if (strcmp (path, "/") != 0) return -ENOENT;
  add_entry (entries, ".", NULL, 0, 0);
  add_entry (entries, "..", NULL, 0, 0);
  void f (h2f_lw_dev_t* dev) { add_entry (entries, dev->name, NULL, 0, 0); }
  h2f_lw_devs_map (&f);
  return 0;
}

static int _open (const char* path, struct fuse_file_info* fi) {
  printf ("cheri-bgas-fuse-devfs -- open\n");
  if (strcmp (path, "/") == 0 || h2f_lw_devs_find (path) != NULL) return 0;
  return -ENOENT;
}

struct fmem_request {
  uint32_t offset;
  uint32_t data;
  uint32_t access_width;
};

static int _ioctl ( const char* path
                  , unsigned int cmd
                  , void* arg
                  , struct fuse_file_info* fi
                  , unsigned int flags
                  , void* data ) {
  printf ("cheri-bgas-fuse-devfs -- ioctl\n");
  sim_ports_t* simports = EXPOSE_SIMPORTS();
  struct fmem_request* fmemReq = (struct fmem_request*) data;

  // compute address and check for in range accesses
  uint32_t addr = fmemReq->offset;
  uint32_t range = 0;
  const h2f_lw_dev_t* dev = h2f_lw_devs_find (path);
  if (dev) {
    printf ("found device \"%s\"\n", dev->name);
    addr += dev->base_addr;
    range += dev->range;
  } else return ERANGE;
  if (fmemReq->offset + fmemReq->access_width > range) return ERANGE;

  // prepare AXI4 access size and byte strobe
  uint8_t size = 0;
  uint8_t strb = 0;
  switch(fmemReq->access_width) {
    case 1: size = 0; strb = 0b00000001; break;
    case 2: size = 1; strb = 0b00000011; break;
    case 4: size = 2; strb = 0b00001111; break;
    default: return -1;
  }

  // perform AXI4 read/write operation
  switch (cmd) {

    case _IOWR('X', 1, struct fmem_request): { // FMEM READ
      printf ("fmem read ioctl\n");
      // send an AXI4 read request AR flit
      t_axi4_arflit* arflit = H2F_LW_AR_(create_flit)(NULL);
      arflit->arid[0] = 0;
      for (int i = 0; i < 4; i++) arflit->araddr[i] = ((uint8_t*) &addr)[i];
      arflit->arlen = 0;
      arflit->arsize = size;
      /*TODO*/ arflit->arburst = 0;
      /*TODO*/ arflit->arlock = 0;
      /*TODO*/ arflit->arcache = 0;
      /*TODO*/ arflit->arprot = 0;
      /*TODO*/ arflit->arqos = 0;
      /*TODO*/ arflit->arregion = 0;
      arflit->aruser[0] = 0;
      H2F_LW_AR_(print_flit)(arflit);
      printf ("\n");
      while (!bub_fifo_Produce (simports->h2flw->ar, (void*) arflit));
      // get an AXI4 read response R flit
      t_axi4_rflit* rflit = H2F_LW_R_(create_flit)(NULL);
      while (!bub_fifo_Consume (simports->h2flw->r, (void*) rflit));
      H2F_LW_R_(print_flit)(rflit);
      printf ("\n");
      // return the response data through the fmem request pointer
      // TODO check rflit->rresp
      for (int i = 0; i < fmemReq->access_width; i++)
        ((uint8_t*) &(fmemReq->data))[i] = rflit->rdata[i];
      return 0;
      break;
    }

    case _IOWR('X', 2, struct fmem_request):  { // FMEM WRITE
      printf ("fmem write ioctl\n");
      // send an AXI4 write request AW flit
      t_axi4_awflit* awflit = H2F_LW_AW_(create_flit)(NULL);
      awflit->awid[0] = 0;
      for (int i = 0; i < 4; i++) awflit->awaddr[i] = ((uint8_t*) &addr)[i];
      awflit->awlen = 0;
      awflit->awsize = size;
      /*TODO*/ awflit->awburst = 0;
      /*TODO*/ awflit->awlock = 0;
      /*TODO*/ awflit->awcache = 0;
      /*TODO*/ awflit->awprot = 0;
      /*TODO*/ awflit->awqos = 0;
      /*TODO*/ awflit->awregion = 0;
      awflit->awuser[0];
      H2F_LW_AW_(print_flit)(awflit);
      printf ("\n");
      while (!bub_fifo_Produce (simports->h2flw->aw, (void*) awflit));
      // send an AXI4 write request W flit
      t_axi4_wflit* wflit = H2F_LW_W_(create_flit)(NULL);
      for (int i = 0; i < 4; i++)
        wflit->wdata[i] = ((uint8_t*) &fmemReq->data)[i];
      wflit->wstrb[0] = strb;
      wflit->wlast = 0b00000001;
      wflit->wuser[0] = 0;
      H2F_LW_W_(print_flit)(wflit);
      printf ("\n");
      while (!bub_fifo_Produce (simports->h2flw->w, (void*) wflit));
      // get an AXI4 write response B flit
      t_axi4_bflit* bflit = H2F_LW_B_(create_flit)(NULL);
      while (!bub_fifo_Consume (simports->h2flw->b, (void*) bflit));
      H2F_LW_B_(print_flit)(bflit);
      printf ("\n");
      // TODO check bflit->bresp
      return 0;
      break;
    }

  }

  return -1;
}

int main (int argc, char** argv)
{
  // grab the path to the simulator's ports folder from the  command line args
  if ((argc < 3) || (argv[1][0] == '-')) {
    printf ("%s PATH_TO_SIMULATOR_PORTS <standard fuse flags>\n", argv[0]);
    return -1;
  }
  char* simports_dir = realpath (argv[1], NULL);
  argv[1] = argv[0];
  argv = &(argv[1]);
  argc--;

  // gather the various fuse operations
  static struct fuse_operations ops = {
    .init    = _init
  , .destroy = _destroy
  , .getattr = _getattr
  , .readdir = _readdir
  , .open    = _open
  , .ioctl   = _ioctl
  };

  printf ("cheri-bgas-fuse-devfs -- fuse_main\n");

  // call fuse main, private data context set to the simulator ports folder
  return fuse_main (argc, argv, &ops, simports_dir);
}
