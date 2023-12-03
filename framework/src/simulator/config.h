#ifndef CONFIG_INCLUDED

#define CONFIG_INCLUDED

#include "xx.h"

#include <vector>
using namespace std;
#define MEMSEG_START "  "
#define OPTION_START "    "

enum SEG_TYPE 
{
    SEG_INVALID = -1,
    SEG_RAM = 1,
    SEG_ROM = 2,
    SEG_MMIO = 3
};

struct SEG_CONTENT
{
    char *file;
    int file_offset;
    int file_size;
    int mem_offset;
};

struct SEG
{
    SEG_TYPE type;
    char *name;
    hw_addr start;
    hw_addr size;
    bool readonly;
    void *ptr;
    vector<SEG_CONTENT*> *contents;
};

struct SIMULATOR_CONFIG
{
    hw_addr vecbase;
    vector<SEG*> *segs;
};


SIMULATOR_CONFIG *generate_xx_config(const char *fuzzware_config_filename);
void *get_ram_ptr(hw_addr addr);


#endif