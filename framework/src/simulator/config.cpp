#include "config.h"
#include "simulator.h"
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

void *get_ram_ptr(hw_addr addr)
{
    for(auto it = config->segs->begin(); it != config->segs->end(); it++)
    {
        if (addr >= (*it)->start && addr < (*it)->start + (*it)->size)
        {
            return (uint8_t*)(*it)->ptr + (addr - (*it)->start);
        }
    }
    return 0;
}
SIMULATOR_CONFIG *generate_xx_config(char *fuzzware_config_filename)
{
    char line[PATH_MAX];
    char *ptr;
    SEG_TYPE type;
    static char file_buf[PATH_MAX];

    bool start = false;

    char *dir_base = dirname(strdup(fuzzware_config_filename));

    SIMULATOR_CONFIG *config = new SIMULATOR_CONFIG();
    config->segs = new vector<SEG*>();

    FILE *fp = fopen(fuzzware_config_filename , "r");
    if(fp == NULL) 
    {
        printf("%s not found\n", fuzzware_config_filename);
        delete config->segs;
        delete config;
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
            config->segs->push_back(new SEG());
            config->segs->back()->type = type;
            while(*ptr == ' ')
                ptr++;
            *strstr(ptr,":") = 0;
            config->segs->back()->name = strdup(ptr);
            config->segs->back()->contents = new vector<SEG_CONTENT*>();
            
        }
        else if (is_option_start(line))
        {
            if(strstr(line,OPTION_START"base_addr:"))
            {
                config->segs->back()->start = strtol(strstr(line,"base_addr: ") + strlen("base_addr: "), 0, 16);
                if(strstr(config->segs->back()->name,"text"))
                    config->vecbase = config->segs->back()->start;
            }
            else if(strstr(line,OPTION_START"permissions:"))
            {
                if(strstr(line,"w"))
                {
                    config->segs->back()->readonly = false;
                }
                else
                {
                    config->segs->back()->readonly = true;
                }
            }
            else if(strstr(line,OPTION_START"size:"))
            {
                config->segs->back()->size = strtol(strstr(line,"size: ") + strlen("size: "), 0, 16);
            }
            else if(strstr(line,OPTION_START"file:"))
            {
                
                config->segs->back()->contents->push_back(new SEG_CONTENT());
                line[strcspn(line, "\n")] = 0;
                strcpy(file_buf,dir_base);
                strcat(file_buf,"/");
                strcat(file_buf, strstr(line,"file: ") + strlen("file: "));
                config->segs->back()->contents->back()->file = strdup(file_buf);
                
            }
            else if(strstr(line,OPTION_START"file_size:"))
            {
                config->segs->back()->contents->back()->file_size = strtol(strstr(line,"file_size: ") + strlen("file_size: "), 0, 16);
            }
            else if(strstr(line,OPTION_START"file_offset:"))
            {

                config->segs->back()->contents->back()->file_offset = strtol(strstr(line,"file_offset: ") + strlen("file_offset: "), 0, 16);

            }
            else if(strstr(line,OPTION_START"mem_offset:"))
            {
                config->segs->back()->contents->back()->mem_offset = strtol(strstr(line,"mem_offset: ") + strlen("mem_offset: "), 0, 16);
            
            }
            else if(strstr(line,OPTION_START"ivt_offset:"))
            {
                if(strstr(config->segs->back()->name,"text"))
                    config->vecbase += strtol(strstr(line,"ivt_offset: ") + strlen("ivt_offset: "), 0, 16);
            }

        }

    }
    printf("parse config file done\n");
    fclose(fp);
    return config;
}