/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * RTAS events handling
 *
 * Copyright (c) 2012 David Gibson, IBM Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
#include "cpu.h"
#include "sysemu/sysemu.h"
#include "sysemu/char.h"
#include "hw/qdev.h"
#include "sysemu/device_tree.h"

#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"

#include <libfdt.h>

struct rtas_error_log {
    uint32_t summary;
#define RTAS_LOG_VERSION_MASK                   0xff000000
#define   RTAS_LOG_VERSION_6                    0x06000000
#define RTAS_LOG_SEVERITY_MASK                  0x00e00000
#define   RTAS_LOG_SEVERITY_ALREADY_REPORTED    0x00c00000
#define   RTAS_LOG_SEVERITY_FATAL               0x00a00000
#define   RTAS_LOG_SEVERITY_ERROR               0x00800000
#define   RTAS_LOG_SEVERITY_ERROR_SYNC          0x00600000
#define   RTAS_LOG_SEVERITY_WARNING             0x00400000
#define   RTAS_LOG_SEVERITY_EVENT               0x00200000
#define   RTAS_LOG_SEVERITY_NO_ERROR            0x00000000
#define RTAS_LOG_DISPOSITION_MASK               0x00180000
#define   RTAS_LOG_DISPOSITION_FULLY_RECOVERED  0x00000000
#define   RTAS_LOG_DISPOSITION_LIMITED_RECOVERY 0x00080000
#define   RTAS_LOG_DISPOSITION_NOT_RECOVERED    0x00100000
#define RTAS_LOG_OPTIONAL_PART_PRESENT          0x00040000
#define RTAS_LOG_INITIATOR_MASK                 0x0000f000
#define   RTAS_LOG_INITIATOR_UNKNOWN            0x00000000
#define   RTAS_LOG_INITIATOR_CPU                0x00001000
#define   RTAS_LOG_INITIATOR_PCI                0x00002000
#define   RTAS_LOG_INITIATOR_MEMORY             0x00004000
#define   RTAS_LOG_INITIATOR_HOTPLUG            0x00006000
#define RTAS_LOG_TARGET_MASK                    0x00000f00
#define   RTAS_LOG_TARGET_UNKNOWN               0x00000000
#define   RTAS_LOG_TARGET_CPU                   0x00000100
#define   RTAS_LOG_TARGET_PCI                   0x00000200
#define   RTAS_LOG_TARGET_MEMORY                0x00000400
#define   RTAS_LOG_TARGET_HOTPLUG               0x00000600
#define RTAS_LOG_TYPE_MASK                      0x000000ff
#define   RTAS_LOG_TYPE_OTHER                   0x00000000
#define   RTAS_LOG_TYPE_RETRY                   0x00000001
#define   RTAS_LOG_TYPE_TCE_ERR                 0x00000002
#define   RTAS_LOG_TYPE_INTERN_DEV_FAIL         0x00000003
#define   RTAS_LOG_TYPE_TIMEOUT                 0x00000004
#define   RTAS_LOG_TYPE_DATA_PARITY             0x00000005
#define   RTAS_LOG_TYPE_ADDR_PARITY             0x00000006
#define   RTAS_LOG_TYPE_CACHE_PARITY            0x00000007
#define   RTAS_LOG_TYPE_ADDR_INVALID            0x00000008
#define   RTAS_LOG_TYPE_ECC_UNCORR              0x00000009
#define   RTAS_LOG_TYPE_ECC_CORR                0x0000000a
#define   RTAS_LOG_TYPE_EPOW                    0x00000040
    uint32_t extended_length;
} QEMU_PACKED;

struct rtas_event_log_v6 {
    uint8_t b0;
#define RTAS_LOG_V6_B0_VALID                          0x80
#define RTAS_LOG_V6_B0_UNRECOVERABLE_ERROR            0x40
#define RTAS_LOG_V6_B0_RECOVERABLE_ERROR              0x20
#define RTAS_LOG_V6_B0_DEGRADED_OPERATION             0x10
#define RTAS_LOG_V6_B0_PREDICTIVE_ERROR               0x08
#define RTAS_LOG_V6_B0_NEW_LOG                        0x04
#define RTAS_LOG_V6_B0_BIGENDIAN                      0x02
    uint8_t _resv1;
    uint8_t b2;
#define RTAS_LOG_V6_B2_POWERPC_FORMAT                 0x80
#define RTAS_LOG_V6_B2_LOG_FORMAT_MASK                0x0f
#define   RTAS_LOG_V6_B2_LOG_FORMAT_PLATFORM_EVENT    0x0e
    uint8_t _resv2[9];
    uint32_t company;
#define RTAS_LOG_V6_COMPANY_IBM                 0x49424d00 /* IBM<null> */
} QEMU_PACKED;

struct rtas_event_log_v6_section_header {
    uint16_t section_id;
    uint16_t section_length;
    uint8_t section_version;
    uint8_t section_subtype;
    uint16_t creator_component_id;
} QEMU_PACKED;

struct rtas_event_log_v6_maina {
#define RTAS_LOG_V6_SECTION_ID_MAINA                0x5048 /* PH */
    struct rtas_event_log_v6_section_header hdr;
    uint32_t creation_date; /* BCD: YYYYMMDD */
    uint32_t creation_time; /* BCD: HHMMSS00 */
    uint8_t _platform1[8];
    char creator_id;
    uint8_t _resv1[2];
    uint8_t section_count;
    uint8_t _resv2[4];
    uint8_t _platform2[8];
    uint32_t plid;
    uint8_t _platform3[4];
} QEMU_PACKED;

struct rtas_event_log_v6_mainb {
#define RTAS_LOG_V6_SECTION_ID_MAINB                0x5548 /* UH */
    struct rtas_event_log_v6_section_header hdr;
    uint8_t subsystem_id;
    uint8_t _platform1;
    uint8_t event_severity;
    uint8_t event_subtype;
    uint8_t _platform2[4];
    uint8_t _resv1[2];
    uint16_t action_flags;
    uint8_t _resv2[4];
} QEMU_PACKED;

struct rtas_event_log_v6_epow {
#define RTAS_LOG_V6_SECTION_ID_EPOW                 0x4550 /* EP */
    struct rtas_event_log_v6_section_header hdr;
    uint8_t sensor_value;
#define RTAS_LOG_V6_EPOW_ACTION_RESET                    0
#define RTAS_LOG_V6_EPOW_ACTION_WARN_COOLING             1
#define RTAS_LOG_V6_EPOW_ACTION_WARN_POWER               2
#define RTAS_LOG_V6_EPOW_ACTION_SYSTEM_SHUTDOWN          3
#define RTAS_LOG_V6_EPOW_ACTION_SYSTEM_HALT              4
#define RTAS_LOG_V6_EPOW_ACTION_MAIN_ENCLOSURE           5
#define RTAS_LOG_V6_EPOW_ACTION_POWER_OFF                7
    uint8_t event_modifier;
#define RTAS_LOG_V6_EPOW_MODIFIER_NORMAL                 1
#define RTAS_LOG_V6_EPOW_MODIFIER_ON_UPS                 2
#define RTAS_LOG_V6_EPOW_MODIFIER_CRITICAL               3
#define RTAS_LOG_V6_EPOW_MODIFIER_TEMPERATURE            4
    uint8_t extended_modifier;
#define RTAS_LOG_V6_EPOW_XMODIFIER_SYSTEM_WIDE           0
#define RTAS_LOG_V6_EPOW_XMODIFIER_PARTITION_SPECIFIC    1
    uint8_t _resv;
    uint64_t reason_code;
} QEMU_PACKED;

struct epow_log_full {
    struct rtas_error_log hdr;
    struct rtas_event_log_v6 v6hdr;
    struct rtas_event_log_v6_maina maina;
    struct rtas_event_log_v6_mainb mainb;
    struct rtas_event_log_v6_epow epow;
} QEMU_PACKED;

#define EVENT_MASK_INTERNAL_ERRORS           0x80000000
#define EVENT_MASK_EPOW                      0x40000000
#define EVENT_MASK_HOTPLUG                   0x10000000
#define EVENT_MASK_IO                        0x08000000

#define _FDT(exp) \
    do { \
        int ret = (exp);                                           \
        if (ret < 0) {                                             \
            fprintf(stderr, "qemu: error creating device tree: %s: %s\n", \
                    #exp, fdt_strerror(ret));                      \
            exit(1);                                               \
        }                                                          \
    } while (0)

void spapr_events_fdt_skel(void *fdt, uint32_t epow_irq)
{
    uint32_t epow_irq_ranges[] = {cpu_to_be32(epow_irq), cpu_to_be32(1)};
    uint32_t epow_interrupts[] = {cpu_to_be32(epow_irq), 0};

    _FDT((fdt_begin_node(fdt, "event-sources")));

    _FDT((fdt_property(fdt, "interrupt-controller", NULL, 0)));
    _FDT((fdt_property_cell(fdt, "#interrupt-cells", 2)));
    _FDT((fdt_property(fdt, "interrupt-ranges",
                       epow_irq_ranges, sizeof(epow_irq_ranges))));

    _FDT((fdt_begin_node(fdt, "epow-events")));
    _FDT((fdt_property(fdt, "interrupts",
                       epow_interrupts, sizeof(epow_interrupts))));
    _FDT((fdt_end_node(fdt)));

    _FDT((fdt_end_node(fdt)));
}

static struct epow_log_full *pending_epow;
static uint32_t next_plid;

static void spapr_powerdown_req(Notifier *n, void *opaque)
{
    sPAPREnvironment *spapr = container_of(n, sPAPREnvironment, epow_notifier);
    struct rtas_error_log *hdr;
    struct rtas_event_log_v6 *v6hdr;
    struct rtas_event_log_v6_maina *maina;
    struct rtas_event_log_v6_mainb *mainb;
    struct rtas_event_log_v6_epow *epow;
    struct tm tm;
    int year;

    if (pending_epow) {
        /* For now, we just throw away earlier events if two come
         * along before any are consumed.  This is sufficient for our
         * powerdown messages, but we'll need more if we do more
         * general error/event logging */
        g_free(pending_epow);
    }
    pending_epow = g_malloc0(sizeof(*pending_epow));
    hdr = &pending_epow->hdr;
    v6hdr = &pending_epow->v6hdr;
    maina = &pending_epow->maina;
    mainb = &pending_epow->mainb;
    epow = &pending_epow->epow;

    hdr->summary = cpu_to_be32(RTAS_LOG_VERSION_6
                               | RTAS_LOG_SEVERITY_EVENT
                               | RTAS_LOG_DISPOSITION_NOT_RECOVERED
                               | RTAS_LOG_OPTIONAL_PART_PRESENT
                               | RTAS_LOG_TYPE_EPOW);
    hdr->extended_length = cpu_to_be32(sizeof(*pending_epow)
                                       - sizeof(pending_epow->hdr));

    v6hdr->b0 = RTAS_LOG_V6_B0_VALID | RTAS_LOG_V6_B0_NEW_LOG
        | RTAS_LOG_V6_B0_BIGENDIAN;
    v6hdr->b2 = RTAS_LOG_V6_B2_POWERPC_FORMAT
        | RTAS_LOG_V6_B2_LOG_FORMAT_PLATFORM_EVENT;
    v6hdr->company = cpu_to_be32(RTAS_LOG_V6_COMPANY_IBM);

    maina->hdr.section_id = cpu_to_be16(RTAS_LOG_V6_SECTION_ID_MAINA);
    maina->hdr.section_length = cpu_to_be16(sizeof(*maina));
    /* FIXME: section version, subtype and creator id? */
    qemu_get_timedate(&tm, spapr->rtc_offset);
    year = tm.tm_year + 1900;
    maina->creation_date = cpu_to_be32((to_bcd(year / 100) << 24)
                                       | (to_bcd(year % 100) << 16)
                                       | (to_bcd(tm.tm_mon + 1) << 8)
                                       | to_bcd(tm.tm_mday));
    maina->creation_time = cpu_to_be32((to_bcd(tm.tm_hour) << 24)
                                       | (to_bcd(tm.tm_min) << 16)
                                       | (to_bcd(tm.tm_sec) << 8));
    maina->creator_id = 'H'; /* Hypervisor */
    maina->section_count = 3; /* Main-A, Main-B and EPOW */
    maina->plid = next_plid++;

    mainb->hdr.section_id = cpu_to_be16(RTAS_LOG_V6_SECTION_ID_MAINB);
    mainb->hdr.section_length = cpu_to_be16(sizeof(*mainb));
    /* FIXME: section version, subtype and creator id? */
    mainb->subsystem_id = 0xa0; /* External environment */
    mainb->event_severity = 0x00; /* Informational / non-error */
    mainb->event_subtype = 0xd0; /* Normal shutdown */

    epow->hdr.section_id = cpu_to_be16(RTAS_LOG_V6_SECTION_ID_EPOW);
    epow->hdr.section_length = cpu_to_be16(sizeof(*epow));
    epow->hdr.section_version = 2; /* includes extended modifier */
    /* FIXME: section subtype and creator id? */
    epow->sensor_value = RTAS_LOG_V6_EPOW_ACTION_SYSTEM_SHUTDOWN;
    epow->event_modifier = RTAS_LOG_V6_EPOW_MODIFIER_NORMAL;
    epow->extended_modifier = RTAS_LOG_V6_EPOW_XMODIFIER_PARTITION_SPECIFIC;

    qemu_irq_pulse(xics_get_qirq(spapr->icp, spapr->epow_irq));
}

static void check_exception(PowerPCCPU *cpu, sPAPREnvironment *spapr,
                            uint32_t token, uint32_t nargs,
                            target_ulong args,
                            uint32_t nret, target_ulong rets)
{
    uint32_t mask, buf, len;
    uint64_t xinfo;

    if ((nargs < 6) || (nargs > 7) || nret != 1) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    xinfo = rtas_ld(args, 1);
    mask = rtas_ld(args, 2);
    buf = rtas_ld(args, 4);
    len = rtas_ld(args, 5);
    if (nargs == 7) {
        xinfo |= (uint64_t)rtas_ld(args, 6) << 32;
    }

    if ((mask & EVENT_MASK_EPOW) && pending_epow) {
        if (sizeof(*pending_epow) < len) {
            len = sizeof(*pending_epow);
        }

        cpu_physical_memory_write(buf, pending_epow, len);
        g_free(pending_epow);
        pending_epow = NULL;
        rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    } else {
        rtas_st(rets, 0, RTAS_OUT_NO_ERRORS_FOUND);
    }
}

void spapr_events_init(sPAPREnvironment *spapr)
{
    spapr->epow_irq = xics_alloc(spapr->icp, 0, 0, false);
    spapr->epow_notifier.notify = spapr_powerdown_req;
    qemu_register_powerdown_notifier(&spapr->epow_notifier);
    spapr_rtas_register(RTAS_CHECK_EXCEPTION, "check-exception",
                        check_exception);
}
