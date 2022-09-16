#ifndef H2F_LW_H
#define H2F_LW_H

/*-
* SPDX-License-Identifier: BSD-2-Clause
*
* Copyright (c) 2022 Alexandre Joannou <aj443@cam.ac.uk>
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

#include <BlueUnixBridges.h>
#include <BlueAXI4UnixBridges.h>
#include <mem_mapped_dev.h>

// list helpers
////////////////////////////////////////////////////////////////////////////////

// H2F LW devices
////////////////////////////////////////////////////////////////////////////////
static const mem_mapped_dev_t h2f_lw_dev_list[] =
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
  , .range     = 0x00004000 }
};
int len_h2f_lw_dev_list = sizeof(h2f_lw_dev_list)/sizeof(mem_mapped_dev_t);
static const mem_mapped_dev_t* h2f_lw_devs_find (const char* path){
  return devs_find(path, h2f_lw_dev_list, len_h2f_lw_dev_list);
}
static void h2f_lw_devs_print () {
  return devs_print(h2f_lw_dev_list, len_h2f_lw_dev_list);
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

//DEF_AXI4_AWFlit(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_AWUSER)
//DEF_AXI4_WFlit(H2F_LW_DATA, H2F_LW_WUSER)
//DEF_AXI4_BFlit(H2F_LW_ID, H2F_LW_BUSER)
//DEF_AXI4_ARFlit(H2F_LW_ID, H2F_LW_ADDR, H2F_LW_ARUSER)
//DEF_AXI4_RFlit(H2F_LW_ID, H2F_LW_DATA, H2F_LW_RUSER)
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

// H2F_LW AXI4 functions
////////////////////////////////////////////////////////////////////////////////
static baub_port_fifo_desc_t* h2f_lw_init (const char* portsPath) {
  size_t len = strlen (portsPath) + 1;
  // H2F LW interface
  /**/h2f_lw_devs_print ();
  char* h2flwPath = (char*) malloc (len + strlen ("/" H2F_LW_FOLDER));
  strcpy (h2flwPath, portsPath);
  strcat (h2flwPath, "/" H2F_LW_FOLDER);
  // return baub port
  return H2F_LW_(fifo_OpenAsSlave)(h2flwPath);
}

#endif
