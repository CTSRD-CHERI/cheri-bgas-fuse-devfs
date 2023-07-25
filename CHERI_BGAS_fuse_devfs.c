/*-
* SPDX-License-Identifier: BSD-2-Clause
*
* Copyright (c) 2022-2023 Alexandre Joannou <aj443@cam.ac.uk>
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
#include <math.h>

#include <CHERI_BGAS_fuse_devfs.h>
#include <H2F_LW.h>
#include <H2F.h>

#define MAX_PATH_LEN 1024

typedef struct {
  char simports_path[MAX_PATH_LEN];
  char workdir_path[MAX_PATH_LEN];
} setup_ctxt_t;

#define EXPOSE_SIMPORTS() ((sim_ports_t*) fuse_get_context()->private_data)

////////////////////////////////////////////////////////////////////////////////

static void* _init (struct fuse_conn_info* conn, struct fuse_config* cfg) {
  printf ("cheri-bgas-fuse-devfs -- init\n");
  // private data initially set to path to simulator ports folder
  setup_ctxt_t* pctxt = (setup_ctxt_t*) fuse_get_context()->private_data;
  // prepare simulation ports
  sim_ports_t* simports = (sim_ports_t*) malloc (sizeof (sim_ports_t));
  // H2F LW interface
  char h2flw_log_path[MAX_PATH_LEN];
  sprintf (h2flw_log_path, "%s/%s", pctxt->workdir_path, "h2flw.log");
  simports->h2flw = h2f_lw_init (pctxt->simports_path, h2flw_log_path);
  // H2F interface
  char h2f_log_path[MAX_PATH_LEN];
  sprintf (h2f_log_path, "%s/%s", pctxt->workdir_path, "h2f.log");
  simports->h2f = h2f_init (pctxt->simports_path, h2f_log_path);
  // F2H interface TODO
  simports->f2h = NULL;
  // return simulator ports
  return (void*) simports;
}

static void _destroy (void* private_data) {
  printf ("cheri-bgas-fuse-devfs -- destroy\n");
  sim_ports_t* simports = EXPOSE_SIMPORTS();
  //TODO f2h_destroy (simports->f2h);
  h2f_destroy (simports->h2f);
  h2f_lw_destroy (simports->h2flw);
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
  //sim_ports_t* simports = EXPOSE_SIMPORTS();
  if (strcmp (path, "/") == 0) {
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
  } else if (   devs_find (path, h2f_lw_devs, n_h2f_lw_devs) != NULL
             || devs_find (path, h2f_devs, n_h2f_devs) != NULL) {
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
  for (int i = 0; i < n_h2f_lw_devs; i++)
    add_entry (entries, h2f_lw_devs[i].name, NULL, 0, 0);
  for (int i = 0; i < n_h2f_devs; i++)
    add_entry (entries, h2f_devs[i].name, NULL, 0, 0);
  return 0;
}

static int _open (const char* path, struct fuse_file_info* fi) {
  printf ("cheri-bgas-fuse-devfs -- open\n");
  if (   strcmp (path, "/") == 0
      || devs_find (path, h2f_lw_devs, n_h2f_lw_devs) != NULL
      || devs_find (path, h2f_devs, n_h2f_devs) != NULL ) return 0;
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

  // find device and initialize axi functions
  const mem_mapped_dev_t* dev = NULL;
  t_axi4_awflit* (*aw_create_flit) (const uint8_t* raw_flit) = NULL;
  t_axi4_wflit*  (*w_create_flit)  (const uint8_t* raw_flit) = NULL;
  t_axi4_bflit*  (*b_create_flit)  (const uint8_t* raw_flit) = NULL;
  t_axi4_arflit* (*ar_create_flit) (const uint8_t* raw_flit) = NULL;
  t_axi4_rflit*  (*r_create_flit)  (const uint8_t* raw_flit) = NULL;
  void (*aw_fprint_flit) (FILE* f, const t_axi4_awflit* flit) = NULL;
  void (*w_fprint_flit)  (FILE* f, const t_axi4_wflit* flit)  = NULL;
  void (*b_fprint_flit)  (FILE* f, const t_axi4_bflit* flit)  = NULL;
  void (*ar_fprint_flit) (FILE* f, const t_axi4_arflit* flit) = NULL;
  void (*r_fprint_flit)  (FILE* f, const t_axi4_rflit* flit)  = NULL;
  axi_sim_port_t* simport = NULL;
  uint64_t offset_mask = (~0 << (int) log2 (fmemReq->access_width));
  if ((dev = devs_find (path, h2f_lw_devs, n_h2f_lw_devs))) {
    aw_create_flit = &H2F_LW_AW_(create_flit);
    w_create_flit  = &H2F_LW_W_(create_flit);
    b_create_flit  = &H2F_LW_B_(create_flit);
    ar_create_flit = &H2F_LW_AR_(create_flit);
    r_create_flit  = &H2F_LW_R_(create_flit);
    aw_fprint_flit = &H2F_LW_AW_(fprint_flit);
    w_fprint_flit  = &H2F_LW_W_(fprint_flit);
    b_fprint_flit  = &H2F_LW_B_(fprint_flit);
    ar_fprint_flit = &H2F_LW_AR_(fprint_flit);
    r_fprint_flit  = &H2F_LW_R_(fprint_flit);
    simport = simports->h2flw;
    offset_mask &= 0x3;
  }
  else if ((dev = devs_find (path, h2f_devs, n_h2f_devs))) {
    aw_create_flit = &H2F_AW_(create_flit);
    w_create_flit  = &H2F_W_(create_flit);
    b_create_flit  = &H2F_B_(create_flit);
    ar_create_flit = &H2F_AR_(create_flit);
    r_create_flit  = &H2F_R_(create_flit);
    aw_fprint_flit = &H2F_AW_(fprint_flit);
    w_fprint_flit  = &H2F_W_(fprint_flit);
    b_fprint_flit  = &H2F_B_(fprint_flit);
    ar_fprint_flit = &H2F_AR_(fprint_flit);
    r_fprint_flit  = &H2F_R_(fprint_flit);
    simport = simports->h2f;
    offset_mask &= 0xf;
  } else return ERANGE;

  // compute address and check for in range accesses
  printf ("found device \"%s\"\n", dev->name);
  uint64_t addr = 0xffffffff & (fmemReq->offset + dev->base_addr);
  uint64_t range = 0xffffffff & dev->range;
  uint64_t flit_offset = addr & offset_mask;
  if (fmemReq->offset + fmemReq->access_width > range) return ERANGE;

  // prepare AXI4 access size and byte strobe
  uint8_t size = 0;
  uint8_t strb = 0;
  switch(fmemReq->access_width) {
    case 1: size = 0; strb = 0b00000001 << flit_offset; break;
    case 2: size = 1; strb = 0b00000011 << flit_offset; break;
    case 4: size = 2; strb = 0b00001111 << flit_offset; break;
    default: return -1;
  }

  // perform AXI4 read/write operation
  switch (cmd) {

    case _IOWR('X', 1, struct fmem_request): { // FMEM READ
      printf ("fmem read ioctl\n");
      // send an AXI4 read request AR flit
      t_axi4_arflit* arflit = ar_create_flit (NULL);
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
      bub_fifo_ProduceElement (simport->fifo->ar, (void*) arflit);
      ar_fprint_flit (simport->logfile, arflit);
      fprintf (simport->logfile, "\n");
      // get an AXI4 read response R flit
      t_axi4_rflit* rflit = r_create_flit (NULL);
      bub_fifo_ConsumeElement (simport->fifo->r, (void*) rflit);
      r_fprint_flit (simport->logfile, rflit);
      fprintf (simport->logfile, "\n");
      fflush (simport->logfile);
      // return the response data through the fmem request pointer
      // TODO check rflit->rresp
      for (int i = 0; i < fmemReq->access_width; i++)
        ((uint8_t*) &(fmemReq->data))[i] = rflit->rdata[flit_offset + i];
      return 0;
      break;
    }

    case _IOWR('X', 2, struct fmem_request):  { // FMEM WRITE
      printf ("fmem write ioctl\n");
      // send an AXI4 write request AW flit
      t_axi4_awflit* awflit = aw_create_flit (NULL);
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
      /**/printf ("fmem write ioctl -- pre log\n");
      aw_fprint_flit (simport->logfile, awflit);
      fprintf (simport->logfile, "\n");
      /**/printf ("fmem write ioctl -- post log\n");
      bub_fifo_ProduceElement (simport->fifo->aw, (void*) awflit);
      // send an AXI4 write request W flit
      t_axi4_wflit* wflit = w_create_flit (NULL);
      for (int i = 0; i < 4; i++)
        wflit->wdata[flit_offset + i] = ((uint8_t*) &fmemReq->data)[i];
      wflit->wstrb[0] = strb;
      wflit->wlast = 0b00000001;
      wflit->wuser[0] = 0;
      w_fprint_flit (simport->logfile, wflit);
      fprintf (simport->logfile, "\n");
      bub_fifo_ProduceElement (simport->fifo->w, (void*) wflit);
      // get an AXI4 write response B flit
      t_axi4_bflit* bflit = b_create_flit (NULL);
      bub_fifo_ConsumeElement (simport->fifo->b, (void*) bflit);
      b_fprint_flit (simport->logfile, bflit);
      fprintf (simport->logfile, "\n");
      fflush (simport->logfile);
      // TODO check bflit->bresp
      return 0;
      break;
    }

  }

  return -1;
}

int main (int argc, char** argv)
{
  // prepate an initial constect to call the fuse_main with
  setup_ctxt_t ctxt;

  // grab the path to the simulator's ports folder from the  command line args
  if ((argc < 3) || (argv[1][0] == '-')) {
    printf ("%s PATH_TO_SIMULATOR_PORTS <standard fuse flags>\n", argv[0]);
    return -1;
  }
  char* simports_dir = realpath (argv[1], NULL);
  strcpy (ctxt.simports_path, simports_dir);
  free (simports_dir);
  argv[1] = argv[0];
  argv = &(argv[1]);
  argc--;

  // remember the current working directory
  char current_workdir_path[MAX_PATH_LEN];
  getcwd(ctxt.workdir_path, MAX_PATH_LEN);

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

  // call fuse main, with initial private data context set
  return fuse_main (argc, argv, &ops, &ctxt);
}
