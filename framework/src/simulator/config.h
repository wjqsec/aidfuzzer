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
int run_config(struct SIMULATOR_CONFIG *config);
void init(int argc, char **argv);