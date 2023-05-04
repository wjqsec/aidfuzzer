#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h> 
#include <sys/types.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#include <glib.h>
#include <string.h>
#include "xx.h"
#include "simulator.h"


struct CONFIG _3dprinter_config = 
{
    .project_dir = "/home/w/hd/iofuzzer/xxfuzzer/framework/target/example",
    .vecbase = 0x8000000,
    .rams = {
                { "zero", 0, 0x1000, false, NULL, 0, 0 },
                { "ram", 0x20000000, 0x20000, false, NULL, 0, 0 },
                { "text", 0x8014000, 0x3000, false, "/home/w/hd/iofuzzer/xxfuzzer/framework/target/example/uEmu.3Dprinter.bin", 0x14000, 0x3000 },
                [3 ... 254] = {  NULL, 0, 0, false, NULL, 0, 0  }
    },
    .roms = {
                { "rom", 0x8000000, 0x14000, "/home/w/hd/iofuzzer/xxfuzzer/framework/target/example/uEmu.3Dprinter.bin", 0, 0x14000},
                [1 ... 254] = {  NULL, 0, 0, NULL, 0, 0  }
    },
    .mmios = {
                { "mmio1", 0x40000000, 0x20000000},
                { "mmio2", 0x1e0000, 0x10000},
                [2 ... 254] = {  NULL, 0, 0 }
    }
};

struct CONFIG _basic_exercises_config = 
{
    .project_dir = "/home/w/hd/iofuzzer/xxfuzzer/framework/target/example",
    .vecbase = 0,
    .rams = {
                { "ram", 0x20000000, 0x100000, false, NULL, 0, 0 },
                { "sram", 0x10000000, 0x8000, false, NULL, 0, 0 },
                { "text", 0, 0x800000, false, "./bin/fuzzware-experiments-main/01-access-modeling-for-fuzzing/pw-discovery/ARCH_PRO/basic_exercises.bin", 0, 0x800000 },
                [3 ... 254] = {  NULL, 0, 0, false, NULL, 0, 0  }
    },
    .roms = {
                [0 ... 254] = {  NULL, 0, 0, NULL, 0, 0  }
    },
    .mmios = {
                { "mmio", 0x40000000, 0x20000000},
                [1 ... 254] = {  NULL, 0, 0 }
    }
};
struct CONFIG _arduino_f103_adc_config = 
{
    .project_dir = "/home/w/hd/iofuzzer/xxfuzzer/framework/target/example",
    .vecbase = 0x8000000,
    .rams = {
                { "ram", 0x20000000, 0x100000, false, NULL, 0, 0 },
                { "text",0x8000000, 0x20000, false, "./bin/fuzzware-experiments-main/01-access-modeling-for-fuzzing/p2im-unittests/F103/ARDUINO-F103-ADC/ARDUINO-F103-ADC.bin",0, 0x16430},
                [2 ... 254] = {  NULL, 0, 0, false, NULL, 0, 0  }
    },
    .roms = {
                [0 ... 254] = {  NULL, 0, 0, NULL, 0, 0  }
    },
    .mmios = {
                { "mmio", 0x40000000, 0x20000000},
                [1 ... 254] = {  NULL, 0, 0 }
    }
};
struct CONFIG _arduino_f103_gpio_config = 
{
    .project_dir = "/home/w/hd/iofuzzer/xxfuzzer/framework/target/example",
    .vecbase = 0x8000000,
    .rams = {
                { "ram", 0x20000000, 0x100000, false, NULL, 0, 0 },
                { "text",0x8000000, 0x20000, false,"./bin/fuzzware-experiments-main/01-access-modeling-for-fuzzing/p2im-unittests/F103/ARDUINO-F103-GPIO/ARDUINO-F103-GPIO.bin",0, 0x13680},
                [2 ... 254] = {  NULL, 0, 0, false, NULL, 0, 0  }
    },
    .roms = {
                [0 ... 254] = {  NULL, 0, 0, NULL, 0, 0  }
    },
    .mmios = {
                { "mmio", 0x40000000, 0x20000000},
                [1 ... 254] = {  NULL, 0, 0 }
    }
};
int main(int argc, char **argv)
{
    run_config(&_3dprinter_config);
}