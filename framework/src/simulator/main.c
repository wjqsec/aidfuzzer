#include <stdbool.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h> 
#include <sys/types.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#include <glib.h>
#include <string.h>
#include "xx.h"
#include "config.h"


int main(int argc, char **argv)
{
    init(argc,argv);
    run_config();
}