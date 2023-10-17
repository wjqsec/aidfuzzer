#ifndef CONFIG_INCLUDED

#define CONFIG_INCLUDED
#include <libgen.h>
#include "xx.h"


#define MEMSEG_START "  "
#define OPTION_START "    "

enum SEG_TYPE 
{
    SEG_INVALID = -1,
    SEG_RAM = 1,
    SEG_ROM = 2,
    SEG_MMIO = 3
};
struct MEM_CONTENT
{
    char *file;
    int file_offset;
    int file_size;
    int mem_offset;
};
struct SEG
{
    enum SEG_TYPE type;
    char *name;
    hw_addr start;
    hw_addr size;
    bool readonly;
    
    int num_content;
    struct MEM_CONTENT content[20];
};

struct SIMULATOR_CONFIG
{
    hw_addr vecbase;
    struct SEG segs[MAX_NUM_MEM_REGION];
};
int run_config();
void init(int argc, char **argv);



static bool is_option_start(char *line)
{
    return !memcmp(line,OPTION_START,strlen(OPTION_START));
}
static bool is_seg_start(char *line)
{
    return !memcmp(line,MEMSEG_START,strlen(MEMSEG_START)) && !is_option_start(line);
}


static struct SIMULATOR_CONFIG *generate_xx_config(char *fuzzware_config_filename)
{
    int index = -1;
    char line[PATH_MAX];
    char *ptr;
    enum SEG_TYPE type = SEG_INVALID;
    static char file_buf[PATH_MAX];

    bool start = false;

    char *dir_base = dirname(strdup(fuzzware_config_filename));
    struct SIMULATOR_CONFIG *config = (struct SIMULATOR_CONFIG *)malloc(sizeof(struct SIMULATOR_CONFIG));
    memset(config, 0, sizeof(struct SIMULATOR_CONFIG));
    FILE *fp = fopen(fuzzware_config_filename , "r");
    if(fp == NULL) 
    {
        printf("%s config not found\n", fuzzware_config_filename);
        free(config);
        return NULL;
    }

    while(1)
    {
        if(!fgets(line, PATH_MAX, fp))
            break;
        if(strstr(line,"symbols:"))
        {
            start = false;
            continue;
        }
        else if(strstr(line,"memory_map:"))
        {
            start = true;
            continue;
        }
        if(!start)
            continue;
        ptr = line;

        if(is_seg_start(line))
        {
            index++;
            if(strstr(line,MEMSEG_START"mmio"))
            {
                type = SEG_MMIO;
            }
            else if(strstr(line,MEMSEG_START"irq_ret") || strstr(line,MEMSEG_START"nvic"))
            {
                type = SEG_INVALID;
            }
            else
            {
                type = SEG_RAM;
            }
            config->segs[index].type = type;
            while(*ptr == ' ')
                ptr++;
            *strstr(ptr,":") = 0;
            config->segs[index].name = strdup(ptr);
            config->segs[index].num_content = -1;
        }
        else if (is_option_start(line))
        {
            if(strstr(line,OPTION_START"base_addr:"))
            {
                config->segs[index].start = strtol(strstr(line,"base_addr: ") + strlen("base_addr: "), 0, 16);
            }
            else if(strstr(line,OPTION_START"permissions:"))
            {
                if(strstr(line,"w"))
                {
                    config->segs[index].readonly = false;
                }
                else
                {
                    config->segs[index].readonly = true;
                }
                config->segs[index].readonly = false;  // we need this for memory content writing
            }
            else if(strstr(line,OPTION_START"size:"))
            {
                config->segs[index].size = strtol(strstr(line,"size: ") + strlen("size: "), 0, 16);
                
                
            }
            else if(strstr(line,OPTION_START"file:"))
            {
                
                config->segs[index].num_content++;
                line[strcspn(line, "\n")] = 0;
                strcpy(file_buf,dir_base);
                strcat(file_buf,"/");
                strcat(file_buf, strstr(line,"file: ") + strlen("file: "));
                config->segs[index].content[config->segs[index].num_content].file = strdup(file_buf);
                
                
            }
            else if(strstr(line,OPTION_START"file_size:"))
            {
                config->segs[index].content[config->segs[index].num_content].file_size = strtol(strstr(line,"file_size: ") + strlen("file_size: "), 0, 16);
            }
            else if(strstr(line,OPTION_START"file_offset:"))
            {

                config->segs[index].content[config->segs[index].num_content].file_offset = strtol(strstr(line,"file_offset: ") + strlen("file_offset: "), 0, 16);

            }
            else if(strstr(line,OPTION_START"mem_offset:"))
            {
                config->segs[index].content[config->segs[index].num_content].mem_offset = strtol(strstr(line,"mem_offset: ") + strlen("mem_offset: "), 0, 16);
            
            }
            else if(strstr(line,OPTION_START"ivt_offset:"))
            {
                config->vecbase = strtol(strstr(line,"ivt_offset: ") + strlen("ivt_offset: "), 0, 16) + config->segs[index].start;
            }

        }

    }
    fclose(fp);
    return config;
}
#endif