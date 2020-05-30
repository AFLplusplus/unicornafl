#ifndef PPCE500_H
#define PPCE500_H

#include "hw/boards.h"

typedef struct PPCE500Params {
    int pci_first_slot;
    int pci_nr_slots;

    /* required -- must at least add toplevel board compatible */
    void (*fixup_devtree)(struct PPCE500Params *params, void *fdt);

    int mpic_version;
    bool has_mpc8xxx_gpio;
    bool has_platform_bus;
    hwaddr platform_bus_base;
    hwaddr platform_bus_size;
    int platform_bus_first_irq;
    int platform_bus_num_irqs;
} PPCE500Params;

void ppce500_init(MachineState *machine, PPCE500Params *params);

#endif
