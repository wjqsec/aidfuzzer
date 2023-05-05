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
struct CONFIG
{
    hwaddr vecbase;
    struct RAM rams[255];
    struct ROM roms[255];
    struct MMIO mmios[255];
};
int run_config(struct CONFIG *config);
void init(int argc, char **argv);