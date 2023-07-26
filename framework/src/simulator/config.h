#define MAX_NUM_MEM_REGION 255
struct RAM
{
    char *name;
    hwaddr start;
    hwaddr size;
    bool readonly;
    char *file;
    int file_offset;
    int file_size;
};
struct ROM
{
    char *name;
    hwaddr start;
    hwaddr size;
    char *file;
    int file_offset;
    int file_size;
};
struct MMIO
{
    char *name;
    hwaddr start;
    hwaddr size;
};
struct SIMULATOR_CONFIG
{
    hwaddr vecbase;
    struct RAM rams[MAX_NUM_MEM_REGION];
    struct ROM roms[MAX_NUM_MEM_REGION];
    struct MMIO mmios[MAX_NUM_MEM_REGION];
};
int run_config();
void init(int argc, char **argv);
static struct SIMULATOR_CONFIG *generate_xx_config(char *fuzzware_config_filename);

#include <libgen.h>
static struct SIMULATOR_CONFIG *generate_xx_config(char *fuzzware_config_filename)
{
    int ram_index = 0;
    int rom_index = 0;
    int mmio_index = 0;
    char line[PATH_MAX];
    char *ptr;

    char base_addr_buf[PATH_MAX];
    char file_buf[PATH_MAX];
    char ivt_offset_buf[PATH_MAX];
    char permissions_buf[PATH_MAX];
    char size_buf[PATH_MAX];

    char final_file[PATH_MAX];
    
    hwaddr base_addr;
    bool readonly;
    hwaddr ivt_offset;
    hwaddr size;

    struct SIMULATOR_CONFIG *config = (struct SIMULATOR_CONFIG *)malloc(sizeof(struct SIMULATOR_CONFIG));
    FILE *fp = fopen(fuzzware_config_filename , "r");
    if(fp == NULL) 
    {
        printf("%s config not found\n", fuzzware_config_filename);
        free(config);
        return NULL;
    }
    while(fgets(line, PATH_MAX, fp))
    {
        ptr = line;
        if(strstr(line,"bss:") || strstr(line,"noinit:") || strstr(line,"ram:"))
        {
            while(*ptr == ' ')
                ptr++;
            *strstr(ptr,":") = 0;
            fgets(base_addr_buf, PATH_MAX, fp);
            fgets(permissions_buf, PATH_MAX, fp);
            fgets(size_buf, PATH_MAX, fp);
            base_addr = strtol(strstr(base_addr_buf,"base_addr: ") + strlen("base_addr: "), 0, 16);
            if(strstr(permissions_buf,"w"))
                readonly = false;
            else
                readonly = true;
            size = strtol(strstr(size_buf,"size: ") + strlen("size: "), 0, 16);
            config->rams[ram_index].name = strdup(ptr);
            config->rams[ram_index].start = base_addr;
            config->rams[ram_index].size = size;
            config->rams[ram_index].readonly = readonly;
            config->rams[ram_index].file = 0;

            ram_index++;
            
        }
        if(strstr(line,"mmio:"))
        {
            while(*ptr == ' ')
                ptr++;
            *strstr(ptr,":") = 0;
            fgets(base_addr_buf, PATH_MAX, fp);
            fgets(permissions_buf, PATH_MAX, fp);
            fgets(size_buf, PATH_MAX, fp);
            base_addr = strtol(strstr(base_addr_buf,"base_addr: ") + strlen("base_addr: "), 0, 16);
            size = strtol(strstr(size_buf,"size: ") + strlen("size: "), 0, 16);

            config->mmios[mmio_index].name = strdup(ptr);
            config->mmios[mmio_index].start = base_addr;
            config->mmios[mmio_index].size = size;


            mmio_index++;

        }
        if(strstr(line,"text:"))
        {
            while(*ptr == ' ')
                ptr++;
            *strstr(ptr,":") = 0;
            fgets(base_addr_buf, PATH_MAX, fp);
            fgets(file_buf, PATH_MAX, fp);
            fgets(ivt_offset_buf, PATH_MAX, fp);
            fgets(permissions_buf, PATH_MAX, fp);
            fgets(size_buf, PATH_MAX, fp);
            file_buf[strcspn(file_buf, "\n")] = 0;

            base_addr = strtol(strstr(base_addr_buf,"base_addr: ") + strlen("base_addr: "), 0, 16);
            ivt_offset = strtol(strstr(ivt_offset_buf,"ivt_offset: ") + strlen("ivt_offset: "), 0, 16);
            size = strtol(strstr(size_buf,"size: ") + strlen("size: "), 0, 16);

            config->rams[ram_index].name = strdup(ptr);
            config->rams[ram_index].start = base_addr;
            config->rams[ram_index].size = size;
            config->rams[ram_index].readonly = false;
            strcpy(final_file,dirname(fuzzware_config_filename));
            strcat(final_file,"/");
            strcat(final_file, strstr(file_buf,"file: ") + strlen("file: "));
            config->rams[ram_index].file = strdup(final_file);
            config->rams[ram_index].file_offset = 0; 
            config->rams[ram_index].file_size = size; 

            config->vecbase = base_addr + ivt_offset;

            ram_index++;  
        }
    }
    config->rams[ram_index].size = 0;
    config->roms[rom_index].size = 0;
    config->mmios[mmio_index].size = 0;
    return config;
}