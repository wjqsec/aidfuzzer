import angr, monkeyhex
from setup_env import from_state_file,from_elf_file
import claripy
import re
import sys
import capstone
import time
from termcolor import colored
from pathlib import Path
import argparse
from config import *
from angr import exploration_techniques
import pyvex.lifting.gym.arm_spotter
import logging
import traceback


# logging.getLogger().setLevel(logging.ERROR)
# logging.getLogger('angr').setLevel('ERROR')
class TextColor:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

# Function to print colorful text with different foreground and background colors
def print_colorful_text(text, foreground_color=''):
    full_text = foreground_color + text + '\033[0m'  # Reset color to default
    print(full_text)

config = Configs()
stack_size = 0x4000
fix_lr = 0xdeadbeef

project = None

class ACCESS_INFO:
    def __init__(self):
        pass
    def __eq__(self, other):
        if self.addr == other.addr and self.type == other.type and self.size == other.size:
            return True
        else:
            return False
    def __hash__(self):
        return hash(hex(self.addr) + self.type) 
    
class IRQ_MODEL:
    def __init__(self):
        self.irq = 0
        self.isr = 0
        self.id = 0
        self.accesses = set()
        self.toend = "n"
        

def irq_model_from_file(modelfilename):
    models = []
    model = None
    if not Path(modelfilename).exists():
        return models
    with open(modelfilename, "r") as f:
        for line in f.readlines():
            if "-" in line:
                if model != None:
                    models.append(model)
                model = IRQ_MODEL()
                model.irq = int(line.split("-")[1],10)
                model.id = int(line.split("-")[2],16)
                model.isr = int(line.split("-")[3],16)
                model.toend = line.split("-")[4].strip()
            else:
                accessinfo = ACCESS_INFO()
                accessinfo.type = line.split(":")[0]
                accessinfo.addr = int(line.split(":")[1].split(" ")[0],16)
                accessinfo.size = int(line.split(":")[1].split(" ")[1],16)
                model.accesses.add(accessinfo)
    if model != None:
        models.append(model)
    return models
                

def write_model_to_file(models,modelfilename):
    with open(modelfilename, "w") as f:
        for model in models:
            f.write("-{}-{}-{}-{}\n".format(model.irq,hex(model.id),hex(model.isr),model.toend))
            f.write("".join(["{}:{} {}\n".format(access.type,hex(access.addr),hex(access.size)) for access in model.accesses]))
            
def get_and_insert_model(models,irq,isr,irq_id):
    for model in models:
        if model.irq == irq and model.isr == isr and model.id == irq_id:
            models.remove(model)
    tmp = IRQ_MODEL()
    tmp.irq = irq
    tmp.isr = isr
    tmp.id = irq_id
    models.append(tmp)
    return tmp

def is_mmio_address(state, addr):
    for mem in config.mems:
        if addr >= mem.start and addr <= mem.start + mem.size:
            if mem.ismmio:
                return True
            else:
                return False
    return False

def is_ast_mmio_address(state, ast):
    try:
        addr = state.solver.eval_one(ast)
    except Exception as e:
        return False

    return is_mmio_address(state, addr)

def is_stack_address(state,addr):
    stack_end = state.regs.sp - stack_size
    stack_base = state.solver.eval_one(state.regs.sp)
    stack_top = state.solver.eval_one(stack_end)
    ret = addr >= stack_top and addr <= stack_base
    return ret

def is_ast_stack_address(state,ast):
    try:
        addr = state.solver.eval_one(ast)
    except Exception as e:
        return False
    return is_stack_address(state,addr)


def is_pointer(addr):
    for mem in config.mems:
        if addr >= mem.start and addr <= mem.start + mem.size:
            if mem.ismmio:
                return False
            else:
                return True
    return False
                
def is_ast_pointer(state,ast):
    try:
        data = state.solver.eval_one(ast)
    except Exception as e:
        return False
    return is_pointer(data)

def is_readonly(state,addr):
    for mem in config.mems:
        if addr >= mem.start and addr <= mem.start + mem.size:
            if mem.isreadonly:
                return True
            else:
                return False
    return False

def is_ast_readonly(state,ast):
    try:
        addr = state.solver.eval_one(ast)
    except Exception as e:
        return False
    return is_readonly(state,addr)


def is_zero(addr):
    return addr == 0

def is_ast_zero(state,ast):
    try:
        addr = state.solver.eval_one(ast)
    except Exception as e:
        return False
    return is_zero(addr)

def is_ast_only_eval_one_value(state,ast):
    try:
        state.solver.eval_one(ast)
        return True
    except Exception as e:
        return False
def ast_cannot_be_zero(state,ast):
    tmp_state = state.copy()

    tmp_state.add_constraints(ast == 0)
    ret = tmp_state.satisfiable()
    tmp_state.solver.constraints.pop()
    tmp_state.solver.reload_solver()
    return not ret

def get_leaf_ast(ast):
    return [leaf for leaf in ast.leaf_asts()]










class SymState:
    def __init__(self):
        self.null_values = set()
        self.value_addr_map = dict()
        self.value_concrete_value_map = dict()

        self.initialized_addrs = set()
    def copy_self(self):
        ret = SymState()
        ret.null_values = self.null_values.copy()
        ret.value_addr_map = self.value_addr_map.copy()
        ret.value_concrete_value_map = self.value_concrete_value_map.copy()

        ret.initialized_addrs = self.initialized_addrs.copy()
        return ret
    
    def get_concrete_value_for_pointers(self,ast):
        ret = []
        for leaf in ast.leaf_asts():
            if leaf in self.value_concrete_value_map:
                ret.append((leaf,self.value_concrete_value_map[leaf]))
        return ret
    
    def addr_already_init(self,addr):
        return addr in self.initialized_addrs
    def init_addr(self,addr):
        self.initialized_addrs.add(addr)

    def get_nullptr_ast_in_ast(self,ast):
        if ast in self.null_values:
            return ast
        ret = None
        for leaf in ast.leaf_asts():    
            if leaf in self.null_values:
                ret = leaf
            elif leaf.symbolic:
                return None
        
        return ret

    def get_addr_for_null_value(self,ast):
        return self.value_addr_map[ast]

#####

def is_valid_read(state):
    disassembly_block = project.factory.block(state.addr, size=4).bytes
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
    md.detail = True
    inses = md.disasm(disassembly_block, state.addr)
    for ins in inses:
        if "ldr" not in ins.mnemonic:
            return False
        if len(ins.operands) < 2 :
            return False
        if "[" not in ins.op_str:
            return False
        if "pc" in ins.op_str:
            return False
        break
    return True

nullptr_func_check_mem = set()

nullptr_data_access_check_mem = set()

mem_access = set()
mem_access_addr = set()

unsolved_func_ptr_addr = set()





class SymPreservePlugin(angr.SimStatePlugin):
    def __init__(self, symstate):
        super(SymPreservePlugin, self).__init__()
        self.syms = symstate.copy_self()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SymPreservePlugin(self.syms)

def try_get_null_access(state,ast,nullptr_ast):
    if ast_cannot_be_zero(state,nullptr_ast):
        return
    
    # if len(state.solver.constraints) > 5:
    #     return

    if state.irqplugin.syms.get_addr_for_null_value(nullptr_ast) not in nullptr_data_access_check_mem:
        print_colorful_text("add mem_read_after dependency pc " + hex(state.addr) + " ast "+ str(ast) + " addr " + hex(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast)),foreground_color=TextColor.GREEN)
    # print("add mem_read_after dependency pc ",hex(state.addr), " ast ",ast," addr ",hex(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast)))
    
    nullptr_data_access_check_mem.add(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast))


def mem_read_before(state):
    pass
   

def mem_read_after(state):
    
    if not is_valid_read(state):
        return
    
    addr = state,state.inspect.mem_read_address
    value = state,state.inspect.mem_read_expr

    if type(addr) is tuple:
        addr = addr[1]
    if type(value) is tuple:
        value = value[1]
    
    nullptr_ast = state.irqplugin.syms.get_nullptr_ast_in_ast(addr)
    if nullptr_ast != None:
        assign_value = state.solver.BVS(f"assign_sym_{hex(state.addr)}", state.inspect.mem_read_length * 8)
        state.inspect.mem_read_expr = assign_value
        state.irqplugin.syms.null_values.add(assign_value)
        state.irqplugin.syms.value_addr_map[assign_value] = state.irqplugin.syms.get_addr_for_null_value(nullptr_ast)
        try_get_null_access(state,addr,nullptr_ast)
        return


    try:
        address = state.solver.eval_one(addr)
        
    except Exception as e:
        pass
    

    concrete_pointers = state.irqplugin.syms.get_concrete_value_for_pointers(addr)

    for concrete_pointer in concrete_pointers:
        state.add_constraints(concrete_pointer[0] == concrete_pointer[1])
        state.solver.reload_solver()
    
    try:
        address = state.solver.eval_one(addr)
    except Exception as e:
        return
    
    if not is_ast_pointer(state,address) or is_ast_stack_address(state,address) or is_ast_readonly(state,address) or state.irqplugin.syms.addr_already_init(address):
        state.inspect.mem_read_expr = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')
        return
    
    if is_ast_mmio_address(state, address):
        state.inspect.mem_read_expr = state.solver.BVS(f"mmio_sym_{hex(address)}", state.inspect.mem_read_length * 8)
        return

    value = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')

    
    try:
        concrete_value = state.solver.eval_one(value)
        if is_ast_stack_address(state,concrete_value) or is_ast_mmio_address(state, concrete_value):
            return
        state.inspect.mem_read_expr = state.solver.BVS(f"mem_sym_{hex(address)}", state.inspect.mem_read_length * 8)
        state.irqplugin.syms.value_concrete_value_map[state.inspect.mem_read_expr] = concrete_value
        if state.inspect.mem_read_length == 4 and concrete_value == 0:
            state.irqplugin.syms.null_values.add(state.inspect.mem_read_expr)
            state.irqplugin.syms.value_addr_map[state.inspect.mem_read_expr] = address
    except Exception as e:
        pass
    
    
    
    
    
    
    return

    

        
def mem_write_after(state):
    addr = state.inspect.mem_write_address
    if type(addr) is tuple:
        addr = addr[1]
    get_memory_access(state,state.addr,addr,state.inspect.mem_read_length)
    nullptr_ast = state.irqplugin.syms.get_nullptr_ast_in_ast(addr)
    if nullptr_ast == None:
        return
    try_get_null_access(state,addr,nullptr_ast)
    if not is_ast_only_eval_one_value(state,addr):
        return
    state.irqplugin.syms.init_addr(state.solver.eval_one(addr))


def call_before(state):

    tmpr0 = state.regs.r0
    state.regs.r0 = state.solver.BVS(f"callr0_sym_{hex(state.addr)}", 32)
    state.solver.add(tmpr0 == state.regs.r0)
    if tmpr0 in state.irqplugin.syms.value_concrete_value_map:
        state.irqplugin.syms.value_concrete_value_map[state.regs.r0] = state.irqplugin.syms.value_concrete_value_map[tmpr0]
    if tmpr0 in  state.irqplugin.syms.null_values:
        state.irqplugin.syms.null_values.add(state.regs.r0)
        state.irqplugin.syms.value_addr_map[state.regs.r0] = state.irqplugin.syms.value_addr_map[tmpr0]


    tmpr1 = state.regs.r1
    state.regs.r1 = state.solver.BVS(f"callr1_sym_{hex(state.addr)}", 32)
    state.solver.add(tmpr1 == state.regs.r1)
    if tmpr1 in state.irqplugin.syms.value_concrete_value_map:
        state.irqplugin.syms.value_concrete_value_map[state.regs.r1] = state.irqplugin.syms.value_concrete_value_map[tmpr1]
    if tmpr1 in  state.irqplugin.syms.null_values:
        state.irqplugin.syms.null_values.add(state.regs.r1)
        state.irqplugin.syms.value_addr_map[state.regs.r1] = state.irqplugin.syms.value_addr_map[tmpr1]

    tmpr2 = state.regs.r2
    state.regs.r2 = state.solver.BVS(f"callr2_sym_{hex(state.addr)}", 32)
    state.solver.add(tmpr2 == state.regs.r2)
    if tmpr2 in state.irqplugin.syms.value_concrete_value_map:
        state.irqplugin.syms.value_concrete_value_map[state.regs.r2] = state.irqplugin.syms.value_concrete_value_map[tmpr2]
    if tmpr2 in  state.irqplugin.syms.null_values:
        state.irqplugin.syms.null_values.add(state.regs.r2)
        state.irqplugin.syms.value_addr_map[state.regs.r2] = state.irqplugin.syms.value_addr_map[tmpr2]

    tmpr3 = state.regs.r3
    state.regs.r3 = state.solver.BVS(f"callr3_sym_{hex(state.addr)}", 32)
    state.solver.add(tmpr3 == state.regs.r3)
    if tmpr3 in state.irqplugin.syms.value_concrete_value_map:
        state.irqplugin.syms.value_concrete_value_map[state.regs.r3] = state.irqplugin.syms.value_concrete_value_map[tmpr3]
    if tmpr3 in  state.irqplugin.syms.null_values:
        state.irqplugin.syms.null_values.add(state.regs.r3)
        state.irqplugin.syms.value_addr_map[state.regs.r3] = state.irqplugin.syms.value_addr_map[tmpr3]



    

def call_statement_before(state):
    
    global project
    len_ = 4
    try:
        pc_addr = state.solver.eval_one(state.addr)
        disassembly_block = project.factory.block(pc_addr, size=len_).bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
        inses = md.disasm(disassembly_block, pc_addr)
        for ins in inses:
            if ("bx" in ins.mnemonic or "blx" in ins.mnemonic) and "lr" not in ins.op_str:
                # print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
                if ins.address != pc_addr:
                    break
                
                addr = getattr(state.regs,ins.op_str)
                
                if not addr.symbolic:
                    break
                
                if addr in state.irqplugin.syms.value_concrete_value_map and state.irqplugin.syms.value_concrete_value_map[addr] != 0:
                    

                    if pc_addr not in  unsolved_func_ptr_addr:
                        unsolved_func_ptr_addr.add(pc_addr)
                        print_colorful_text("resolve a function at " + hex(pc_addr) + "  to pointer " + hex(state.irqplugin.syms.value_concrete_value_map[addr]), foreground_color = TextColor.YELLOW)
                    state.add_constraints(addr == state.irqplugin.syms.value_concrete_value_map[addr])
                    state.solver.reload_solver()
                    break
                nullptr_ast = state.irqplugin.syms.get_nullptr_ast_in_ast(addr)
                if nullptr_ast == None:
                    break
                
                if state.irqplugin.syms.get_addr_for_null_value(nullptr_ast) not in nullptr_func_check_mem:
                    nullptr_func_check_mem.add(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast))
                    print_colorful_text("add nullptr  pc  " + hex(pc_addr) + "  ast  "+ str(nullptr_ast) + "  addr   " + hex(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast)),foreground_color = TextColor.BLUE)
                
                
                
                try_get_null_access(state,addr,nullptr_ast)
    
    except Exception as e:
        pass


def mrs_write_after(state):
    global project
    len_ = 4
    try:
        pc_addr = state.solver.eval_one(state.regs.pc)
        disassembly_block = project.factory.block(pc_addr, size=len_).bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
        inses = md.disasm(disassembly_block, pc_addr)
        for ins in inses:
            if ins.mnemonic == "mrs" and "ipsr" not in ins.op_str:
                setattr(state.regs,ins.op_str.split(",")[0],state.solver.BVS(f"mrs", 32))
            break

    except Exception as e:
        pass

def new_cons(state):
    pass
    # print(hex(state.addr),state.inspect.added_constraints)

def is_memory_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem'

def is_memory_read_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'read'

def is_memory_write_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'write'




def get_memory_access(state,ins_addr,addr,size):
    if not is_ast_pointer(state,addr):
        return
    if is_ast_stack_address(state,addr):
        return
    if is_ast_readonly(state,addr):
        return
    if is_ast_zero(state,addr):
        return
    if not is_ast_only_eval_one_value(state,addr):
        return
    if is_ast_mmio_address(state,addr):
        return
    if ins_addr in  mem_access_addr:
        return
    addr = state.solver.min(addr)
    if addr in mem_access:
        return
    mem_access.add(addr)
    print_colorful_text("watchpoint " + hex(ins_addr) + "  " + hex(addr),foreground_color=TextColor.RED)

                
        
    

def main():
    global project

    start_time = time.time()
    parser = argparse.ArgumentParser(description="irq dataflow modeling",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--state", help="irq state binary file")
    parser.add_argument("-i", "--irq",  help="irq number")
    parser.add_argument("-v", "--vecbase",  help="vecbase")
    parser.add_argument("-d", "--id",  help="id")
    parser.add_argument("-o", "--output", help="output file name")
    parser.add_argument("-c","--config",  help="fuzzware config file")

    args = parser.parse_args()
    pyvex.lifting.gym.arm_spotter.set_current_irq(int(args.irq,10))

    config.from_fuzzware_config_file(args.config)

    spiller = angr.exploration_techniques.Spiller(max=50)
    # suggest = angr.exploration_techniques.Suggestions()
    # loopser = angr.exploration_techniques.LocalLoopSeer(bound=1)       
    project, initial_state = from_state_file(args.state)

    start_addr = int(args.vecbase,16) + 4 * int(args.irq,10)
    irq_val = initial_state.memory.load(start_addr, 4, endness='Iend_LE')
    irq_val = initial_state.solver.eval_one(irq_val)
    initial_state.regs.pc = irq_val
    initial_state.regs.lr = fix_lr

    models = irq_model_from_file(args.output)
    model = get_and_insert_model(models,int(args.irq,10),irq_val,int(args.id,16))
    
    logging.info("start pc:  ",hex(irq_val))

    # initial_state.inspect.b("mem_read",when=angr.BP_BEFORE, action=mem_read_before)
    initial_state.inspect.b("mem_read",when=angr.BP_AFTER, action=mem_read_after)
    initial_state.inspect.b("mem_write",when=angr.BP_AFTER, action=mem_write_after)
    initial_state.inspect.b("call",when=angr.BP_BEFORE, action=call_before)
    initial_state.inspect.b("instruction",when=angr.BP_AFTER, action=mrs_write_after)
    initial_state.inspect.b("statement",when=angr.BP_BEFORE, action=call_statement_before)
    
    
    
    initial_state.register_plugin('irqplugin', SymPreservePlugin(SymState()))

    simgr = project.factory.simgr(initial_state)

    simgr.use_technique(spiller)
    # simgr.use_technique(suggest)
    # simgr.use_technique(loopser)
    

    active_state_addr = set()
    for i in range(60):
        to_remove = []
        for active_state in simgr.active:
            try:
                pc_addr = active_state.solver.eval_one(active_state.regs.pc)
                # for zephyr, a very complex operation happened

                if pc_addr == 0x4105Bb:
                    to_remove.append(active_state)
                if pc_addr == fix_lr:
                    model.toend = "y"
                    to_remove.append(active_state)
            except Exception as e:
                pass
        for r in to_remove:
            simgr.active.remove(r)
        
        if active_state.addr not in active_state_addr:
            active_state_addr.add(active_state.addr)
            print(simgr.active)
        
        
        simgr.step(thumb=True)


    
    print(model.toend)
    for ptr in mem_access:
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = ptr
        access.size = 4
        access.type = "mem"
        model.accesses.add(access)

    for ptr in nullptr_func_check_mem:
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = ptr
        access.size = 4
        access.type = "func"
        model.accesses.add(access)

    for ptr in nullptr_data_access_check_mem:
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = ptr
        access.size = 4
        access.type = "dependency"
        model.accesses.add(access)

    write_model_to_file(models,args.output)
    end_time = time.time()
    logging.info("irq total time: {}".format(end_time-start_time))
    

if __name__ == '__main__':
    main()
            
    
    
