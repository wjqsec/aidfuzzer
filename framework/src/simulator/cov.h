#ifndef COV_INCLUDED
#define COV_INCLUDED

#include <set>
#include <stdio.h>
#include <string>
#include "xx.h"
using namespace std;

void init_bbl_filter(string *filter_file);
void translate_bbl(hw_addr pc,bbl_id id);
#endif