#include "cov.h"
#include "simulator.h"
set<hw_addr> filter_bbls;
void init_bbl_filter(string *filter_file)
{
    char buffer[256];
    if (*filter_file != "")
    {
        FILE *f = fopen(filter_file->c_str(),"r");
        while (fgets(buffer, sizeof(buffer), f) != NULL) 
        {
            buffer[strcspn(buffer, "\n")] = '\0';
            filter_bbls.insert(strtol(buffer, NULL, 16));
        }
        fclose(f);
    }
}
void translate_bbl(hw_addr pc,bbl_id id)
{
    total_unique_bbls.insert(pc);
    #ifdef DBG
    if(f_cov_log && (filter_bbls.size() == 0 || filter_bbls.find(pc) != filter_bbls.end()))
        fprintf(f_cov_log,"%x ",pc);
    #endif
}