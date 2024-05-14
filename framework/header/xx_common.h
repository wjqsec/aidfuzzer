#ifndef XX_COMMON_INCLUDED

#define XX_COMMON_INCLUDED
#include <glib.h>

#define MEMORY_ACCESS_CALLBACK
//#define MEMORY_ACCESS_LOG


#ifdef MEMORY_ACCESS_LOG
#define PRECISE_PC_EACH_INS
#endif 

#define MAX_NUM_MEM_REGION 255

#define NUM_WATCHPOINT (1 << 20)
#define NUM_WATCHPOINT_PER_SLOT 50

#define MILISECONS_PER_BBL 10000

#define EXCP_INTERRUPT 	0x10000 /* async interruption */
#define EXCP_HLT        0x10001 /* hlt instruction reached */
#define EXCP_DEBUG      0x10002 /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED     0x10003 /* cpu is halted (waiting for external event) */
#define EXCP_YIELD      0x10004 /* cpu wants to yield timeslice to another */
#define EXCP_ATOMIC     0x10005 /* stop-the-world and emulate atomic */


static const char *QEMU_EXIT_NAMES[] = {
    "EXCP_INTERRUPT",
    "EXCP_HLT",
    "EXCP_DEBUG" ,
    "EXCP_HALTED",
    "EXCP_YIELD",
    "EXCP_ATOMIC"
};





typedef struct _XXSimulator
{
    bool enable_gdb_dbg;
}XXSimulator;

typedef enum _qemu_plugin_mem_rw_ {
    QEMU_PLUGIN_MEM_R_ = 1,
    QEMU_PLUGIN_MEM_W_,
    QEMU_PLUGIN_MEM_RW_,
}qemu_plugin_mem_rw_;





typedef mmio_val (*mmio_read_cb)(void *opaque,hw_addr addr_offset,unsigned size);
typedef void (*mmio_write_cb)(void *opaque,hw_addr addr_offset,mmio_val data,unsigned size);

typedef void (*pre_thread_exec_cb)(void); 
typedef bool (*exec_bbl_cb)(hw_addr pc,bbl_id id);
typedef void (*exec_func_cb)(hw_addr pc,reg_val *return_val);
typedef void (*translate_bbl_cb)(hw_addr pc,bbl_id id);

typedef void (*post_thread_exec_cb)(int exec_ret);
typedef void (*nostop_watchpoint_cb)(hw_addr vaddr,hw_addr len,reg_val val,void *data);
typedef void (*mem_access_cb)(hw_addr vaddr,reg_val val,uint32_t flag);


typedef struct _NOSTOP_WATCHPOINT
{
    hw_addr addr;
    hw_addr len;
    qemu_plugin_mem_rw_ flag;
    nostop_watchpoint_cb cb;
    void *data;
}NOSTOP_WATCHPOINT;

#ifdef __cplusplus
extern "C" {
#endif
    XXSimulator *create_simulator(bool dbg);     
    void qemu_init(int,char**);
    void init_simulator(XXSimulator * s);
    void exec_simulator(XXSimulator *s);
    int thread_loop(bool debug);

    void register_pre_thread_exec_hook(pre_thread_exec_cb cb);
    void register_exec_bbl_hook(exec_bbl_cb cb);
    void register_exec_specific_bbl_hook(hw_addr addr,exec_bbl_cb cb);
    void register_exec_func_hook(hw_addr addr,exec_func_cb cb);
    void register_mem_access_log_hook(mem_access_cb cb);
    void register_post_thread_exec_hook(post_thread_exec_cb cb);
    void register_translate_bbl_hook(translate_bbl_cb cb);
    void register_armm_ppb_default_read_hook(mmio_read_cb cb);
    void register_armm_ppb_default_write_hook(mmio_write_cb cb);

    void write_ram(hw_addr addr, hw_addr size, void *buf);  
    void read_ram(hw_addr addr, hw_addr size, void *buf);
    void rom_write(hw_addr addr, hw_addr len, void *buf);
    void* add_ram_region(char *name,hw_addr start, hw_addr size, bool readonly);
    void add_rom_region(char *name,hw_addr start, hw_addr size);
    void add_mmio_region(char *name, hw_addr start, hw_addr size, mmio_read_cb mmio_read_cb, mmio_write_cb mmio_write_cb,void * opaque);
    void load_file_ram(void *ptr,char *filename, int file_offset, int mem_offset, int file_size, int mem_size);
    void zero_ram(void *ptr,hw_addr size);
    void load_file_rom(char *filename,hw_addr addr, int file_offset, int mem_offset, int file_size);
    
    int target_pagesize(void);
    void get_dirty_pages(hw_addr addr,hw_addr size, unsigned long dirty[]);
    NOSTOP_WATCHPOINT* insert_nostop_watchpoint(hw_addr addr, hw_addr len, qemu_plugin_mem_rw_ flag, nostop_watchpoint_cb cb,void *data);
    void delete_nostop_watchpoint(NOSTOP_WATCHPOINT *watchpoint);
#ifdef __cplusplus
}
#endif


__attribute__ ((unused)) static const char* get_qemu_exit_name(int exit)
{
    return QEMU_EXIT_NAMES[exit - EXCP_INTERRUPT];
}





typedef struct _BBL_Hook
{
    hw_addr addr;
    exec_bbl_cb cb;
    void *data;
}BBL_Hook;

typedef struct _Func_Hook
{
    hw_addr addr;
    exec_func_cb cb;
    void *data;
}Func_Hook;


extern NOSTOP_WATCHPOINT **nostop_watchpoints;
extern uint8_t *mem_has_watchpoints;

extern mem_access_cb mem_access_log_func;
extern translate_bbl_cb translate_bbl_func;
extern exec_bbl_cb exec_bbl_func;
extern GArray* specific_bbl_hooks;
extern GArray* func_hooks;
extern int64_t bbl_counts;

extern mmio_read_cb ppb_default_read_func;
extern mmio_write_cb ppb_default_write_func;
#endif
