#ifndef MIS_UTL_INCLUDED
#define MIS_UTL_INCLUDED

#include <execinfo.h>
inline static void fatal(const char *msg)
{
    printf("%s",msg);
    fflush(stdout);
    exit(0);
}


#define alloc_printf(_str...) ({ \
    char* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) fatal("Whoa, snprintf() fails?!"); \
    _tmp = (char*)calloc(1,_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

static void print_trace (void)
{
  void *array[10];
  char **strings;
  int size, i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);
  if (strings != NULL)
  {

    printf ("Obtained %d stack frames.\n", size);
    for (i = 0; i < size; i++)
      printf ("%s\n", strings[i]);
  }

  free (strings);
}
#endif