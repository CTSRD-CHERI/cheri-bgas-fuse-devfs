#ifndef H2F_H
#define H2F_H

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

#include <mem_mapped_dev.h>
#include <BlueUnixBridges.h>
#include <BlueAXI4UnixBridges.h>
#include <CHERI_BGAS_fuse_devfs.h>

// H2F devices
////////////////////////////////////////////////////////////////////////////////

static const mem_mapped_dev_t h2f_devs[] =
{ { .name      = "ddr_uncached"
  , .base_addr = 0x80000000
  , .range     = 0x40000000 },
  { .name      = "ddr_cached"
  , .base_addr = 0xC0000000
  , .range     = 0x40000000 }
};
int n_h2f_devs = sizeof(h2f_devs)/sizeof(mem_mapped_dev_t);

// H2F AXI4 port parameters
////////////////////////////////////////////////////////////////////////////////

#define H2F_FOLDER "h2f"

#ifndef H2F_ID
#define H2F_ID 4
#endif
#ifndef H2F_ADDR
#define H2F_ADDR 32 // top 32 bit set through the dedicated ctrl on H2F_LW port
#endif
#ifndef H2F_DATA
#define H2F_DATA 128
#endif
#ifndef H2F_AWUSER
#define H2F_AWUSER 0
#endif
#ifndef H2F_WUSER
#define H2F_WUSER 0
#endif
#ifndef H2F_BUSER
#define H2F_BUSER 0
#endif
#ifndef H2F_ARUSER
#define H2F_ARUSER 0
#endif
#ifndef H2F_RUSER
#define H2F_RUSER 0
#endif

DEF_AXI4_API( H2F_ID, H2F_ADDR, H2F_DATA
            , H2F_AWUSER, H2F_WUSER, H2F_BUSER
            , H2F_ARUSER, H2F_RUSER
            , h2f )

#define _H2F_( H2F_ID, H2F_ADDR, H2F_DATA \
             , H2F_AWUSER, H2F_WUSER, H2F_BUSER \
             , H2F_ARUSER, H2F_RUSER \
             , sym ) \
  AXI4_( H2F_ID, H2F_ADDR, H2F_DATA \
       , H2F_AWUSER, H2F_WUSER, H2F_BUSER \
       , H2F_ARUSER, H2F_RUSER \
       , h2f, sym )
#define H2F_(sym) _H2F_( H2F_ID, H2F_ADDR, H2F_DATA \
                       , H2F_AWUSER, H2F_WUSER, H2F_BUSER \
                       , H2F_ARUSER, H2F_RUSER \
                       , sym )

#define _H2F_AW_(H2F_ID, H2F_ADDR, H2F_AWUSER, sym) \
  AXI4_AW_(H2F_ID, H2F_ADDR, H2F_AWUSER, h2f, sym)
#define H2F_AW_(sym) _H2F_AW_(H2F_ID, H2F_ADDR, H2F_AWUSER, sym)

#define _H2F_W_(H2F_DATA, H2F_WUSER, sym) AXI4_W_(H2F_DATA, H2F_WUSER, h2f, sym)
#define H2F_W_(sym) _H2F_W_(H2F_DATA, H2F_WUSER, sym)

#define _H2F_B_(H2F_ID, H2F_BUSER, sym) AXI4_B_(H2F_ID, H2F_BUSER, h2f, sym)
#define H2F_B_(sym) _H2F_B_(H2F_ID, H2F_BUSER, sym)

#define _H2F_AR_(H2F_ID, H2F_ADDR, H2F_ARUSER, sym) \
  AXI4_AR_(H2F_ID, H2F_ADDR, H2F_ARUSER, h2f, sym)
#define H2F_AR_(sym) _H2F_AR_(H2F_ID, H2F_ADDR, H2F_ARUSER, sym)

#define _H2F_R_(H2F_ID, H2F_DATA, H2F_RUSER, sym) \
  AXI4_R_(H2F_ID, H2F_DATA, H2F_RUSER, h2f, sym)
#define H2F_R_(sym) _H2F_R_(H2F_ID, H2F_DATA, H2F_RUSER, sym)

static axi_sim_port_t* h2f_init (const char* portpath, const char* logpath) {
  axi_sim_port_t* axi_sim_port = malloc (sizeof (axi_sim_port_t));
  // H2F interface
  size_t len = strlen (portpath) + 1;
  /**/devs_print (h2f_devs, n_h2f_devs);
  char* h2fPath = (char*) malloc (len + strlen ("/" H2F_FOLDER));
  strcpy (h2fPath, portpath);
  strcat (h2fPath, "/" H2F_FOLDER);
  axi_sim_port->fifo = H2F_(fifo_OpenAsSlave)(h2fPath);
  // H2F logstream
  axi_sim_port->logfile = fopen (logpath, "w+");
  //TODO check for fopen error
  free (h2fPath);
  return axi_sim_port;
}

static void h2f_destroy (axi_sim_port_t* axi_sim_port) {
  fclose (axi_sim_port->logfile);
  baub_fifo_Close (axi_sim_port->fifo);
  free (axi_sim_port);
}

#endif
