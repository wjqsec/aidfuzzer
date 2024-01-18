#include "cov.h"
#include "simulator.h"
#include <errno.h>
set<hw_addr> filter_bbls;
void init_bbl_filter(string *filter_file)
{
    char buffer[256];
    if (*filter_file != "")
    {
        FILE *f = fopen(filter_file->c_str(),"r");
        if (f)
        {
            while (fgets(buffer, sizeof(buffer), f) != NULL) 
            {
                buffer[strcspn(buffer, "\n")] = '\0';
                filter_bbls.insert(strtol(buffer, NULL, 16));
            }
            fclose(f);
        }
    }
}
void translate_bbl(hw_addr pc,bbl_id id)
{
    if(total_unique_bbls.find(pc) == total_unique_bbls.end())
    {
        if(filter_bbls.size() == 0 || filter_bbls.find(pc) != filter_bbls.end())
        {
            total_unique_bbls.insert(pc);
        }
    }
}

void dump_coverage(const char *filename)
{
    FILE *f = fopen(filename,"w");
    if(f)
    {
        fprintf(f,"%s","EZCOV VERSION: 1\n");
        for(auto it = total_unique_bbls.begin(); it != total_unique_bbls.end(); it++)
        {
            fprintf(f,"0x%08x, 4, [ MAIN ]\n",*it);
        }
        fclose(f);
    }
}