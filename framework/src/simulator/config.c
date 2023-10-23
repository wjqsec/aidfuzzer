#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
static bool is_option_start(char *line)
{
    return !memcmp(line,OPTION_START,strlen(OPTION_START));
}
static bool is_seg_start(char *line)
{
    return !memcmp(line,MEMSEG_START,strlen(MEMSEG_START)) && !is_option_start(line);
}


SIMULATOR_CONFIG *generate_xx_config(char *fuzzware_config_filename)
{
    int index = -1;
    char line[PATH_MAX];
    char *ptr;
    SEG_TYPE type = SEG_INVALID;
    static char file_buf[PATH_MAX];

    bool start = false;

    char *dir_base = dirname(strdup(fuzzware_config_filename));

    SIMULATOR_CONFIG *config = (SIMULATOR_CONFIG *)malloc(sizeof(SIMULATOR_CONFIG));
    memset(config, 0, sizeof(SIMULATOR_CONFIG));

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
                config->segs[index].contents[config->segs[index].num_content].file = strdup(file_buf);
                
                
            }
            else if(strstr(line,OPTION_START"file_size:"))
            {
                config->segs[index].contents[config->segs[index].num_content].file_size = strtol(strstr(line,"file_size: ") + strlen("file_size: "), 0, 16);
            }
            else if(strstr(line,OPTION_START"file_offset:"))
            {

                config->segs[index].contents[config->segs[index].num_content].file_offset = strtol(strstr(line,"file_offset: ") + strlen("file_offset: "), 0, 16);

            }
            else if(strstr(line,OPTION_START"mem_offset:"))
            {
                config->segs[index].contents[config->segs[index].num_content].mem_offset = strtol(strstr(line,"mem_offset: ") + strlen("mem_offset: "), 0, 16);
            
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