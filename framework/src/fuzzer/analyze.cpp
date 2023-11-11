#include <vector>
#include <set>
#include <map>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <string.h>
#include <algorithm>         /* Definition of AT_* constants */
#include <random>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <dirent.h>
#include <sys/time.h>
#include <iostream>
#include <iterator>
#include <sys/shm.h>
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/stat.h>
#include <execinfo.h>
#include <stdarg.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <time.h>
#include <stdio.h>
#include "fuzzer.h"
#include "mis_utl.h"
#include "iofuzzer.h"
#include "mutator.h"
#include "stream.h"
#include "queue_entry.h"
#include "simulator.h"
#include "model.h"
#include "stream_loader.h"
using namespace std;

int main(int argc, char **argv)
{
    char filename[PATH_MAX];
    FILE *f_output;
    char *input_dir;
    while ((opt = getopt(argc, argv, "i:o:")) != -1) 
    {
        switch (opt) {
        case 'i':
            input_dir = optarg;
            break;
        case 'o':
            f_output = fopen(optarg,"w");
            break;    
        default: /* '?' */
            printf("Usage error\n");
            exit(0);
        }
    }

    DIR* dir;
    queue_entry *q = (queue_entry *)malloc(sizeof(queue_entry));
    struct dirent* dir_entry;
    dir = opendir(input_dir);
    if (dir == NULL) {
        fatal("opendir error");
    }
    while ((dir_entry = readdir(dir)) != NULL) 
    {
        if (dir_entry->d_type == DT_REG  && strstr(dir_entry->d_name,"queue_")) 
        {
            
            sprintf(filename,"%s/%s",queue_dir,dir_entry->d_name);
            FILE *f = fopen(filename,"rb");
            fread(q,offsetof(input_stream,offset_to_save),1,f);
            
        }
    }
    closedir(dir);

    
    
}