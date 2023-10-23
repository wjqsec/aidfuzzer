#ifndef CONFIG_INCLUDED

#define CONFIG_INCLUDED

#include "xx.h"


#define MEMSEG_START "  "
#define OPTION_START "    "

typedef enum _SEG_TYPE 
{
    SEG_INVALID = -1,
    SEG_RAM = 1,
    SEG_ROM = 2,
    SEG_MMIO = 3
}SEG_TYPE;

typedef struct _SEG_CONTENT
{
    char *file;
    int file_offset;
    int file_size;
    int mem_offset;
}SEG_CONTENT;

typedef struct _SEG
{
    SEG_TYPE type;
    char *name;
    hw_addr start;
    hw_addr size;
    bool readonly;
    
    int num_content;
    SEG_CONTENT contents[20];
}SEG;

typedef struct _SIMULATOR_CONFIG
{
    hw_addr vecbase;
    SEG segs[MAX_NUM_MEM_REGION];
}SIMULATOR_CONFIG;


SIMULATOR_CONFIG *generate_xx_config(char *fuzzware_config_filename);



#endif