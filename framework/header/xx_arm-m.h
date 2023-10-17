#ifndef XX_ARM_M_INCLUDED

#define XX_ARM_M_INCLUDED
#include <stdint.h>
#include <glib.h>
typedef uint32_t hw_addr;
typedef uint32_t reg_val;
typedef uint64_t xreg_val;
typedef uint16_t irq_val;
typedef uint32_t bbl_id;

typedef uint64_t mmio_val;

#define EXCP_UDEF            1   /* undefined instruction */
#define EXCP_SWI             2   /* software interrupt */
#define EXCP_PREFETCH_ABORT  3
#define EXCP_DATA_ABORT      4
#define EXCP_IRQ             5
#define EXCP_FIQ             6
#define EXCP_BKPT            7
#define EXCP_EXCEPTION_EXIT  8   /* Return from v7M exception.  */
#define EXCP_KERNEL_TRAP     9   /* Jumped to kernel code page.  */
#define EXCP_HVC            11   /* HyperVisor Call */
#define EXCP_HYP_TRAP       12
#define EXCP_SMC            13   /* Secure Monitor Call */
#define EXCP_VIRQ           14
#define EXCP_VFIQ           15
#define EXCP_SEMIHOST       16   /* semihosting call */
#define EXCP_NOCP           17   /* v7M NOCP UsageFault */
#define EXCP_INVSTATE       18   /* v7M INVSTATE UsageFault */
#define EXCP_STKOF          19   /* v8M STKOF UsageFault */
#define EXCP_LAZYFP         20   /* v7M fault during lazy FP stacking */
#define EXCP_LSERR          21   /* v8M LSERR SecureFault */
#define EXCP_UNALIGNED      22   /* v7M UNALIGNED UsageFault */
#define EXCP_DIVBYZERO      23   /* v7M DIVBYZERO UsageFault */

#define ARMV7M_EXCP_RESET   1
#define ARMV7M_EXCP_NMI     2
#define ARMV7M_EXCP_HARD    3
#define ARMV7M_EXCP_MEM     4
#define ARMV7M_EXCP_BUS     5
#define ARMV7M_EXCP_USAGE   6
#define ARMV7M_EXCP_SECURE  7
#define ARMV7M_EXCP_SVC     11
#define ARMV7M_EXCP_DEBUG   12
#define ARMV7M_EXCP_PENDSV  14
#define ARMV7M_EXCP_SYSTICK 15



static const char *ARM_INTC_NAMES[] = {
    0,
    "EXCP_UDEF",
    "EXCP_SWI",
    "EXCP_PREFETCH_ABORT",
    "EXCP_DATA_ABORT",
    "EXCP_IRQ",
    "EXCP_FIQ",
    "EXCP_BKPT",
    "EXCP_EXCEPTION_EXIT",
    "EXCP_KERNEL_TRAP",
    "EXCP_HVC",
    "EXCP_HYP_TRAP",
    "EXCP_SMC",
    "EXCP_VIRQ",
    "EXCP_VFIQ",
    "EXCP_SEMIHOST",
    "EXCP_NOCP",
    "EXCP_INVSTATE",
    "EXCP_STKOF",
    "EXCP_LAZYFP",
    "EXCP_LSERR",
    "EXCP_UNALIGNED",
    "EXCP_DIVBYZERO"
};

static const char *ARM_NVIC_NAMES[] = {
    0,
    "ARMV7M_EXCP_RESET",
    "ARMV7M_EXCP_NMI",
    "ARMV7M_EXCP_HARD",
    "ARMV7M_EXCP_MEM",
    "ARMV7M_EXCP_BUS",
    "ARMV7M_EXCP_USAGE",
    "ARMV7M_EXCP_SECURE",
    "ARMV7M_EXCP_SVC" ,
    "ARMV7M_EXCP_DEBUG" ,
    "ARMV7M_EXCP_PENDSV" ,
    "ARMV7M_EXCP_SYSTICK"
};
typedef struct _ARM_CPU_STATE
{
    reg_val regs[16]; 
    xreg_val xregs[32];
    reg_val xpsr;
}ARM_CPU_STATE;



typedef bool (*do_arm_interrupt_cb)(int32_t exec_index); 
typedef void (*exec_nvic_cb)(irq_val irq);
typedef void (*enable_nvic_cb)(irq_val irq);
typedef void (*set_nvic_vecbase_cb)(hw_addr addr, int secure);
typedef void (*enable_arm_interrupt_cb)(void);
typedef void (*disable_arm_interrupt_cb)(void);


void get_arm_cpu_state(ARM_CPU_STATE *state);
void set_arm_cpu_state(ARM_CPU_STATE *state);
void *save_arm_ctx_state(void);
void restore_arm_ctx_state(void* state);
void delete_arm_ctx_state(void* state);
bool insert_nvic_intc(irq_val irq);
irq_val get_enabled_nvic_irq(irq_val **irqs);
void reset_arm_reg(void);
void set_armv7_init_vecbase(hw_addr addr);
hw_addr get_arm_precise_pc(void);
hw_addr get_arm_pc(void);
reg_val get_arm_lr(void);

void register_do_arm_interrupt_hook(do_arm_interrupt_cb cb);
void register_exec_nvic_hook(exec_nvic_cb cb);
void register_enable_nvic_hook(enable_nvic_cb cb);
void register_set_nvic_vecbase_hook(set_nvic_vecbase_cb cb);
void register_enable_arm_interrupt_hook(enable_arm_interrupt_cb cb);
void register_disable_arm_interrupt_hook(disable_arm_interrupt_cb cb);
hw_addr get_nvic_vecbase(void);
irq_val get_arm_v7m_is_handler_mode(void);

__attribute__ ((unused)) static const char* get_arm_intc_name(int intc)
{
    return ARM_INTC_NAMES[intc];
}
__attribute__ ((unused)) static const char * get_arm_nvic_name(irq_val irq)
{
    return ARM_NVIC_NAMES[irq];
}

extern hw_addr precise_pc;
#include "xx_common.h"
#endif