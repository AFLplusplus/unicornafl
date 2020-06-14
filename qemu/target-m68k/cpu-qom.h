/*
 * QEMU Motorola 68k CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef QEMU_M68K_CPU_QOM_H
#define QEMU_M68K_CPU_QOM_H

#include "qom/cpu.h"

/**
 * M68kCPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * A Motorola 68k CPU model.
 */
typedef struct M68kCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    void (*parent_reset)(CPUState *cpu);
} M68kCPUClass;

/**
 * M68kCPU:
 * @env: #CPUM68KState
 *
 * A Motorola 68k CPU.
 */
typedef struct M68kCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUM68KState env;

    struct M68kCPUClass cc;
} M68kCPU;

#define M68K_CPU(uc, obj) ((M68kCPU *)obj)
#define M68K_CPU_CLASS(uc, klass) ((M68kCPUClass *)klass)
#define M68K_CPU_GET_CLASS(uc, obj) (&((M68kCPU *)obj)->cc)

static inline M68kCPU *m68k_env_get_cpu(CPUM68KState *env)
{
    return container_of(env, M68kCPU, env);
}

#define ENV_GET_CPU(e) CPU(m68k_env_get_cpu(e))

#define ENV_OFFSET offsetof(M68kCPU, env)

void m68k_cpu_do_interrupt(CPUState *cpu);
bool m68k_cpu_exec_interrupt(CPUState *cpu, int int_req);
hwaddr m68k_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);

void m68k_cpu_exec_enter(CPUState *cs);
void m68k_cpu_exec_exit(CPUState *cs);

#endif
