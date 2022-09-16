#ifndef MEM_MAPPED_DEV_H
#define MEM_MAPPED_DEV_H

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

#include <stdint.h>

typedef struct mem_mapped_dev {
  const char* name;
  const uint32_t base_addr;
  const uint32_t range;
} mem_mapped_dev_t;

static const mem_mapped_dev_t* devs_find (const char* path, const mem_mapped_dev_t devs[], int len_devs) {
  for (int i = 0; i < len_devs; i++)
    if (strcmp (path+1, devs[i].name) == 0)
        return &devs[i];
  return NULL;
}

static void devs_print (const mem_mapped_dev_t devs[], int len_devs) {
  for (int i = 0; i < len_devs; i++)
    printf ( "name: %15s, base_addr: 0x%08x, range: 0x%08x\n"
           , devs[i].name, devs[i].base_addr, devs[i].range );
}

#endif
