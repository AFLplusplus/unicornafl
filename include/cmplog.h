/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#include <stdint.h>
#include "config.h"

#define CMPLOG_LVL_MAX 3

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 2)

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 0
#define CMP_TYPE_RTN 1

struct cmp_header {  // 16 bit = 2 bytes

  unsigned hits : 6;       // up to 63 entries, we have CMP_MAP_H = 32
  unsigned shape : 5;      // 31+1 bytes max
  unsigned type : 1;       // 2: cmp, rtn
  unsigned attribute : 4;  // 16 for arithmetic comparison types

} __attribute__((packed));

struct cmp_operands {

  uint64_t v0;
  uint64_t v0_128;
  uint64_t v0_256_0;  // u256 is unsupported by any compiler for now, so future use
  uint64_t v0_256_1;
  uint64_t v1;
  uint64_t v1_128;
  uint64_t v1_256_0;
  uint64_t v1_256_1;
  uint8_t  unused[8];  // 2 bits could be used for "is constant operand"

} __attribute__((packed));

struct cmpfn_operands {

  uint8_t v0[32];
  uint8_t v0_len;
  uint8_t v1[32];
  uint8_t v1_len;

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};

/* Execs the child */

struct afl_forkserver;
void cmplog_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif

