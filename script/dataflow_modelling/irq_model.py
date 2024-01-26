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
from colorful_print import *
import time

logging.getLogger('angr').setLevel('ERROR')
MAX_LOOP_TIMES = 0x50
TIMEOUT_SECONDS = 60 * 2

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
        if not mem.ismmio:
            continue
        if addr >= mem.start and addr <= mem.start + mem.size:
            return True
    return False

def is_ast_mmio_address(state, ast):
    try:
        addr = state.solver.eval_one(ast)
    except Exception as e:
        return False

    return is_mmio_address(state, addr)

def is_ast_concrete_mmio_address(state,ast):
    if claripy.is_true(ast.symbolic):
        return False
    else:
        return is_mmio_address(state,state.solver.eval(ast))
    
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
        if mem.ismmio:
            continue
        if mem.name == "text":
            continue
        if addr >= mem.start and addr <= mem.start + mem.size and mem.start != 0:
            return True
    return False


def is_text_pointer(addr):
    for mem in config.mems:
        if mem.name == "text":
            if addr >= mem.start and addr <= mem.start + mem.size:
                return True
    return False

def is_ast_pointer(state,ast):
    try:
        data = state.solver.eval_one(ast)
    except Exception as e:
        return False
    return is_pointer(data)

def is_ast_concrete_pointer(state,ast):
    if claripy.is_true(ast.symbolic):
        return False
    else:
        return is_pointer(state.solver.eval(ast))

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
        self.addr_value_map = dict()
        self.value_addr_map = dict()
        self.value_concrete_value_map = dict()
        self.initialized_addrs = set()
        self.return_state = False
        self.bbl_hit_counts = dict()
    def copy_self(self):
        ret = SymState()
        ret.null_values = self.null_values.copy()
        ret.addr_value_map = self.addr_value_map.copy()
        ret.value_addr_map = self.value_addr_map.copy()
        ret.value_concrete_value_map = self.value_concrete_value_map.copy()
        ret.initialized_addrs = self.initialized_addrs.copy()
        ret.return_state = self.return_state
        ret.bbl_hit_counts = self.bbl_hit_counts.copy()
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

    def get_nullptr_ast_in_ast(self,state,ast):
        ret = None
        for leaf in ast.leaf_asts():     
            if leaf in self.null_values:
                ret = leaf
            elif leaf.symbolic:
                return None
            elif is_ast_concrete_pointer(state,leaf) or is_ast_concrete_mmio_address(state,leaf):
                return None
        
        return ret

    def get_addr_for_null_value(self,ast):
        return self.value_addr_map[ast]

#####

def get_read_type(state):
    disassembly_block = project.factory.block(state.addr, size=4).bytes
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
    md.detail = True
    inses = md.disasm(disassembly_block, state.addr)
    for ins in inses:
        if "ldr" not in ins.mnemonic:
            return None
        if len(ins.operands) < 2 :
            return None
        if "[" not in ins.op_str:
            return None
        if "pc" in ins.op_str:
            return "pc"
        break
    return "normal"

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

def try_get_null_access(state,ast):

    nullptr_ast = state.irqplugin.syms.get_nullptr_ast_in_ast(state,ast)
    if nullptr_ast == None:
        return nullptr_ast
    if ast_cannot_be_zero(state,nullptr_ast):
        return nullptr_ast
    # if len(state.solver.constraints) > 5:
    #     return

    if state.irqplugin.syms.get_addr_for_null_value(nullptr_ast) not in nullptr_data_access_check_mem:
        print_colorful_text("add dependency pc " + hex(state.addr) + " ast "+ str(ast) + " addr " + hex(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast)),foreground_color=TextColor.GREEN)
    
    nullptr_data_access_check_mem.add(state.irqplugin.syms.get_addr_for_null_value(nullptr_ast))

    return nullptr_ast


def mem_read_after(state):

    
    addr = state,state.inspect.mem_read_address
    value = state,state.inspect.mem_read_expr

    if type(addr) is tuple:
        addr = addr[1]
    if type(value) is tuple:
        value = value[1]
    
    # read_type = get_read_type(state)
    
    nullptr_ast = try_get_null_access(state,addr)
    if nullptr_ast != None:
        state.inspect.mem_read_expr = state.solver.BVS(f"assign_sym_{hex(state.addr)}", state.inspect.mem_read_length * 8)
        state.irqplugin.syms.null_values.add(state.inspect.mem_read_expr)
        state.irqplugin.syms.value_addr_map[state.inspect.mem_read_expr] = state.irqplugin.syms.value_addr_map[nullptr_ast]
        return
    
    

    concrete_pointers = state.irqplugin.syms.get_concrete_value_for_pointers(addr)

    for concrete_pointer in concrete_pointers:
        state.add_constraints(concrete_pointer[0] == concrete_pointer[1])
        state.solver.reload_solver()
    
    try:
        address = state.solver.eval_one(addr)
    except Exception as e:
        return
    
    
    if is_ast_mmio_address(state, address):
        state.irqplugin.syms.init_addr(address)
        state.inspect.mem_read_expr = state.solver.BVS(f"mmio_sym_{hex(state.addr)}", state.inspect.mem_read_length * 8)
        return
    
    if not is_ast_pointer(state,address) or is_ast_stack_address(state,address) or is_ast_readonly(state,address) or state.irqplugin.syms.addr_already_init(address):
        state.inspect.mem_read_expr = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')
        return
    
    
    

    
    value = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')

    
    try:
        concrete_value = state.solver.eval_one(value)
    except Exception as e:
        return 
    

    if is_ast_stack_address(state,concrete_value) or is_ast_mmio_address(state, concrete_value) or is_pointer(concrete_value):
        state.inspect.mem_read_expr = state.solver.BVV(concrete_value,state.inspect.mem_read_length * 8)
        return
    if address in state.irqplugin.syms.addr_value_map:
        state.inspect.mem_read_expr = state.irqplugin.syms.addr_value_map[address]
    else:      
        state.inspect.mem_read_expr = state.solver.BVS(f"mem_sym_{hex(state.addr)}", state.inspect.mem_read_length * 8)
        state.irqplugin.syms.addr_value_map[address] = state.inspect.mem_read_expr
        state.irqplugin.syms.value_concrete_value_map[state.inspect.mem_read_expr] = concrete_value
        if state.inspect.mem_read_length == 4 and (concrete_value == 0 or concrete_value == 0xffffffff):
            state.irqplugin.syms.null_values.add(state.inspect.mem_read_expr)
            state.irqplugin.syms.value_addr_map[state.inspect.mem_read_expr] = address
    

        
def mem_write_after(state):
    addr = state.inspect.mem_write_address
    value = state.inspect.mem_write_expr
    if type(addr) is tuple:
        addr = addr[1]
    if type(value) is tuple:
        value = value[1]
    

    if addr in state.irqplugin.syms.null_values:
        return
    if not is_ast_only_eval_one_value(state,addr):
        return

    
    get_memory_access(state,state.addr,addr,state.inspect.mem_read_length)

    state.irqplugin.syms.init_addr(state.solver.eval_one(addr))
    state.memory.store(state.solver.eval_one(addr),value,disable_actions=True,inspect=False, endness='Iend_LE')




not_call_ins = set()
def call_statement_before(state):
    if state.addr in not_call_ins:
        return
    global project
    len_ = 4
    try:
        pc_addr = state.solver.eval_one(state.addr)
        disassembly_block = project.factory.block(pc_addr, size=len_).bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
        inses = md.disasm(disassembly_block, pc_addr)
        for ins in inses:
            if ("bx" in ins.mnemonic or "blx" in ins.mnemonic) and "lr" not in ins.op_str:
                if ins.address != pc_addr:
                    break
                
                addr = getattr(state.regs,ins.op_str)
                
                
                if not addr.symbolic:
                    break
                
                
                if addr in state.irqplugin.syms.null_values:
                    

                    if state.irqplugin.syms.value_addr_map[addr] not in nullptr_func_check_mem:
                        # if pc_addr == 0x1427 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008F4:  #ex for  ffd_ncp rfd_ncp
                        #     break
                        
                        # if pc_addr == 0x1427 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008ec:  #ex for  no bcn ffd_ncp  no bcn rfd_ncp
                        #     break

                        # if pc_addr == 0x1427 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008e8:  #ex for app eddemo
                        #     break

                        # if pc_addr == 0x139b and state.irqplugin.syms.value_addr_map[addr] >= 0x20000A7C:  #ex for coord ncp
                        #     break

                        # if pc_addr == 0x15b3 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008F4:  #ex for ctr ncp
                        #     break

                        # if pc_addr == 0x134b and state.irqplugin.syms.value_addr_map[addr] >= 0x200004C8:  #ex for mac no beacon sleep
                        #     break

                        # if pc_addr == 0x1427 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008f0:  #ex for peer2peer
                        #     break

                        # if pc_addr == 0x15b3 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008F4:  #ex for serial if ncp
                        #     break

                        # if pc_addr == 0x149f and state.irqplugin.syms.value_addr_map[addr] >= 0x200004C8:  #ex for single button ctr ncp
                        #     break

                        # if pc_addr == 0x15b3 and state.irqplugin.syms.value_addr_map[addr] >= 0x200008F4:  #ex for tgt ncp
                        #     break

                        if pc_addr == 0x80065Db and state.irqplugin.syms.value_addr_map[addr] >= 0x20000E24:  #ex for taulab
                            break

                        print_colorful_text("add null funcptr pc " + hex(state.addr) + "  " + hex(state.irqplugin.syms.value_addr_map[addr]) + "  " + str(addr),foreground_color = TextColor.BLUE)
                        nullptr_func_check_mem.add(state.irqplugin.syms.value_addr_map[addr])
                    # try_get_null_access(state,addr)
                    break
                
                if addr in state.irqplugin.syms.value_concrete_value_map and state.irqplugin.syms.value_concrete_value_map[addr] != 0:
                    if pc_addr not in  unsolved_func_ptr_addr:
                        unsolved_func_ptr_addr.add(pc_addr)
                        print_colorful_text("resolve a function at " + hex(pc_addr) + "  "  + str(addr) + "  to pointer " + hex(state.irqplugin.syms.value_concrete_value_map[addr]), foreground_color = TextColor.YELLOW)
                    state.add_constraints(addr == state.irqplugin.syms.value_concrete_value_map[addr])
                    state.solver.reload_solver()
                    break
            else:
                not_call_ins.add(state.addr)
    except Exception as e:
        pass


def call_before(state):
    if not is_ast_only_eval_one_value(state,state.inspect.function_address):
        return
    address = state.solver.eval_one(state.inspect.function_address)
    
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

not_mrs_ins = set()
def mrs_write_after(state):

    global project
    if not is_ast_only_eval_one_value(state,state.regs.pc):
        return

    address = state.solver.eval_one(state.regs.pc)
    len_ = 4
    if address == fix_lr or address in not_mrs_ins:
        return
    try:
        pc_addr = state.solver.eval_one(state.regs.pc)
        disassembly_block = project.factory.block(pc_addr, size=len_).bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
        inses = md.disasm(disassembly_block, pc_addr)
        for ins in inses:
            if ins.mnemonic == "mrs" and "ipsr" not in ins.op_str:
                setattr(state.regs,ins.op_str.split(",")[0],state.solver.BVS(f"mrs", 32))
            else:
                not_mrs_ins.add(address)
            break

    except Exception as e:
        pass


def ins_ret(state):
    original_r0 = state.regs.r0
    state.regs.r0 = state.solver.BVS(f"ret_sym_{hex(state.addr)}", 32)
    try:
        value = state.solver.eval_one(original_r0)
        state.irqplugin.syms.value_concrete_value_map[state.regs.r0] = value
    except Exception as e:
        pass
    
    state.irqplugin.syms.return_state = True

def new_cons(state):
    pass

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
    if is_ast_mmio_address(state,addr):
        return
    if ins_addr in mem_access_addr:
        return
    addr = state.solver.eval_one(addr)
    if addr in mem_access:
        return
    mem_access_addr.add(ins_addr)
    mem_access.add(addr)
    print_colorful_text("watchpoint " + hex(ins_addr) + "  " + hex(addr),foreground_color=TextColor.RED)

                

def is_mmio_loop(state):
    return False
    last_jump = state.history.jump_guards[-1]
    return "mmio" in str(last_jump) and state.addr in state.irqplugin.syms.bbl_hit_counts


    
    

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
    loopser = angr.exploration_techniques.LocalLoopSeer(bound=0x20)       
    project, initial_state = from_state_file(args.state)

    start_addr = int(args.vecbase,16) + 4 * int(args.irq,10)
    irq_val = initial_state.memory.load(start_addr, 4, endness='Iend_LE')
    irq_val = initial_state.solver.eval_one(irq_val)
    initial_state.regs.pc = irq_val
    initial_state.regs.lr = fix_lr

    models = irq_model_from_file(args.output)
    model = get_and_insert_model(models,int(args.irq,10),irq_val,int(args.id,16))
    
    logging.info("start pc:  ",hex(irq_val))

   
    initial_state.inspect.b("mem_read",when=angr.BP_AFTER, action=mem_read_after)
    initial_state.inspect.b("mem_write",when=angr.BP_AFTER, action=mem_write_after)
    initial_state.inspect.b("call",when=angr.BP_BEFORE, action=call_before)
    initial_state.inspect.b("instruction",when=angr.BP_AFTER, action=mrs_write_after)
    initial_state.inspect.b("statement",when=angr.BP_BEFORE, action=call_statement_before)
    initial_state.inspect.b("return",when=angr.BP_AFTER, action=ins_ret)
    # initial_state.inspect.b("reg_write",when=angr.BP_AFTER, action=reg_write_after)
    
    
    
    
    initial_state.register_plugin('irqplugin', SymPreservePlugin(SymState()))

    simgr = project.factory.simgr(initial_state)

    # simgr.use_technique(spiller)
    # simgr.use_technique(suggest)
    # simgr.use_technique(loopser)
    


    visited_ret_addrs = set()
    visited_bbls_addrs = set()
    
    pending_loop_states = []
    start_time = time.time()

    s_state = None
    while True:
        states_to_add = []
        print(simgr.active) 
        for state in simgr.active:

            visited_bbls_addrs.add(state.addr)
            if state.addr == fix_lr:
                model.toend = "y"
                continue

            if not is_text_pointer(state.addr):
                continue
            
            
            if state.addr not in state.irqplugin.syms.bbl_hit_counts:
                state.irqplugin.syms.bbl_hit_counts[state.addr] = 1
            else:
                state.irqplugin.syms.bbl_hit_counts[state.addr] += 1
            if state.irqplugin.syms.bbl_hit_counts[state.addr] > MAX_LOOP_TIMES:
                continue
            
            if state.irqplugin.syms.return_state:
                if state.addr in visited_ret_addrs:
                    pending_loop_states.append(state)
                else: 
                    visited_ret_addrs.add(state.addr)
                    states_to_add.append(state)
                state.irqplugin.syms.bbl_hit_counts.clear()
                state.irqplugin.syms.return_state = False
                continue
                

            try:
                succ = state.step()
            except Exception as e:
                continue
            
            
            
            if len(succ.successors) == 0:
                pass
            elif len(succ.successors) == 1:
                if not is_ast_only_eval_one_value(succ.successors[0],succ.successors[0].regs.pc):
                    continue
                if succ.successors[0].addr == state.addr:
                    continue
                if succ.successors[0].addr not in visited_bbls_addrs:
                        states_to_add.append(succ.successors[0])
                else:
                    pending_loop_states.append(succ.successors[0])
    
            elif len(succ.successors) == 2:

                succ1 = succ.successors[0]
                succ2 = succ.successors[1]
                
                succesors1 = []
                succesors2 = []

                dominator = None
                
                succ1_erro = False
                succ2_erro = False

                try:
                    if succ1.addr == fix_lr:
                        states_to_add.append(succ1)
                    simgr = project.factory.simgr(succ1)
                    for i in range(2):
                        if state.addr in [state.addr for state in simgr.active]:
                            break
                        succesors1 += [state for state in simgr.active]
                        simgr.step()
                        # succesors1 = [succ_grand_child.addr for succ_grand_child in succ1.step(thumb=True).successors]
                except Exception as e:
                    succ1_erro = True
 
                try:
                    if succ2.addr == fix_lr:
                        states_to_add.append(succ2)
                    simgr = project.factory.simgr(succ2)
                    for i in range(2):
                        if state.addr in [state.addr for state in simgr.active]:
                            break
                        succesors2 += [state for state in simgr.active]
                        simgr.step()
                    # succesors2 = [succ_grand_child.addr for succ_grand_child in succ2.step(thumb=True).successors]

                except Exception as e:
                    succ2_erro = True

                
                

                if succ1_erro and succ2_erro:
                    continue
                elif succ1_erro:
                    states_to_add.append(succ2)
                    continue
                elif succ2_erro:
                    states_to_add.append(succ1)
                    continue
                    
                if succ2.addr == state.addr:
                    dominator = succ1
                elif succ1.addr == state.addr:
                    dominator = succ2
                elif succ1.addr >= succ2.addr and succ1.addr < succ2.addr + succ2.block().size:
                    dominator = succ2
                elif succ2.addr >= succ1.addr and succ2.addr < succ1.addr + succ1.block().size:
                    dominator = succ1
                else:
                    if any([succ1.addr >= state.addr and succ1.addr < state.addr + state.block().size for state in succesors2]):
                        dominator = succ2
                    elif any([succ2.addr >= state.addr and succ2.addr < state.addr + state.block().size for state in succesors1]):
                        dominator = succ1

                if dominator != None:
                    if dominator.addr not in visited_bbls_addrs:
                        states_to_add.append(dominator)
                    else:
                        pending_loop_states.append(dominator)
                else:
                    if succ1.addr not in visited_bbls_addrs:
                        states_to_add.append(succ1)
                    else:
                        pending_loop_states.append(succ1)
                    if succ2.addr not in visited_bbls_addrs:
                        states_to_add.append(succ2)
                    else:
                        pending_loop_states.append(succ2)
                
            else:
                print("why more than 2 successors, exit")
                exit(0)

               
        
        simgr.active.clear()
        for state in states_to_add:
            simgr.active.append(state)
        if len(simgr.active) == 0:
            for i in range(50):
                if len(pending_loop_states) != 0:
                    simgr.active.append(pending_loop_states.pop(0))
        if len(simgr.active) == 0:
            break
        if (time.time() - start_time) >  TIMEOUT_SECONDS and len(states_to_add) == 0:
            break


    
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
            
    
    
