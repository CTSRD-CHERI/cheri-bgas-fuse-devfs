#ifndef H2F_LW_H
#define H2F_LW_H

/*-
* SPDX-License-Identifier: BSD-2-Clause
*
* Copyright (c) 2022-2023 Alexandre Joannou <aj443@cam.ac.uk>
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

#include <stdio.h>
#include <stdlib.h>

#include <mem_mapped_dev.h>
#include <BlueUnixBridges.h>
#include <BlueAXI4UnixBridges.h>
#include <CHERI_BGAS_fuse_devfs.h>

// H2F LW devices
////////////////////////////////////////////////////////////////////////////////

static const mem_mapped_dev_t h2f_lw_devs[] =
{ { .name      = "debug_unit"
  , .base_addr = 0x00000000
  , .range     = 0x00001000 },
  { .name      = "irqs"
  , .base_addr = 0x00001000
  , .range     = 0x00001000 },
  { .name      = "misc"
  , .base_addr = 0x00002000
  , .range     = 0x00001000 },
  { .name      = "uart0"
  , .base_addr = 0x00003000
  , .range     = 0x00001000 },
  { .name      = "uart1"
  , .base_addr = 0x00004000
  , .range     = 0x00001000 },
  { .name      = "h2f_addr_ctrl"
  , .base_addr = 0x00005000
  , .range     = 0x00001000 },
  { .name      = "virtual_device"
  , .base_addr = 0x00008000
  , .range     = 0x00004000 },
  { .name      = "bert_a"
  , .base_addr = 0x00140000
  , .range     = 0x00000100 },
  { .name      = "bert_b"
  , .base_addr = 0x00141000
  , .range     = 0x00000100 },
  { .name      = "bert_c"
  , .base_addr = 0x00142000
  , .range     = 0x00000100 },
  { .name      = "bert_d"
  , .base_addr = 0x00143000
  , .range     = 0x00000100 }
};
int n_h2f_lw_devs = sizeof(h2f_lw_devs)/sizeof(mem_mapped_dev_t);

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
            , H2F_LW_ARUSER, H2F_LW_RUSER
            , h2f_lw )

#define _H2F_LW_( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA \
                , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER \
                , H2F_LW_ARUSER, H2F_LW_RUSER \
                , sym ) \
  AXI4_( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA \
       , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER \
       , H2F_LW_ARUSER, H2F_LW_RUSER \
       , h2f_lw, sym )
#define H2F_LW_(sym) _H2F_LW_( H2F_LW_ID, H2F_LW_ADDR, H2F_LW_DATA \
                             , H2F_LW_AWUSER, H2F_LW_WUSER, H2F_LW_BUSER \
                             , H2F_LW_ARUSER, H2F_LW_RUSER \
                             , sym )

#define _H2F_LW_AW_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER, sym) \
  AXI4_AW_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER, h2f_lw, sym)
#define H2F_LW_AW_(sym) _H2F_LW_AW_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER, sym)

#define _H2F_LW_W_(H2F_LW_DATA, H2F_LW_WUSER, sym) \
  AXI4_W_(H2F_LW_DATA, H2F_LW_WUSER, h2f_lw, sym)
#define H2F_LW_W_(sym) _H2F_LW_W_(H2F_LW_DATA, H2F_LW_WUSER, sym)

#define _H2F_LW_B_(H2F_LW_ID, H2F_LW_BUSER, sym) \
  AXI4_B_(H2F_LW_ID, H2F_LW_BUSER, h2f_lw, sym)
#define H2F_LW_B_(sym) _H2F_LW_B_(H2F_LW_ID, H2F_LW_BUSER, sym)

#define _H2F_LW_AR_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER, sym) \
  AXI4_AR_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER, h2f_lw, sym)
#define H2F_LW_AR_(sym) _H2F_LW_AR_(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER, sym)

#define _H2F_LW_R_(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER, sym) \
  AXI4_R_(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER, h2f_lw, sym)
#define H2F_LW_R_(sym) _H2F_LW_R_(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER, sym)

static axi_sim_port_t* h2f_lw_init (const char* portpath, const char* logpath) {
  axi_sim_port_t* axi_sim_port = malloc (sizeof (axi_sim_port_t));
  // H2F LW interface
  size_t len = strlen (portpath) + 1;
  /**/devs_print (h2f_lw_devs, n_h2f_lw_devs);
  char* h2flwPath = (char*) malloc (len + strlen ("/" H2F_LW_FOLDER));
  strcpy (h2flwPath, portpath);
  strcat (h2flwPath, "/" H2F_LW_FOLDER);
  axi_sim_port->fifo = H2F_LW_(fifo_OpenAsSlave)(h2flwPath);
  // H2F LW logstream
  if ((axi_sim_port->logfile = fopen (logpath, "w")) == NULL) {
    fprintf(stderr, "Failed fopen(\"%s\", \"w\"): ", logpath);
    perror(NULL);
    exit (EXIT_FAILURE);
  }
  free (h2flwPath);
  return axi_sim_port;
}

static void h2f_lw_destroy (axi_sim_port_t* axi_sim_port) {
  fclose (axi_sim_port->logfile);
  baub_fifo_Close (axi_sim_port->fifo);
  free (axi_sim_port);
}

#endif
