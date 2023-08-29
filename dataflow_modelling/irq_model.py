import angr, monkeyhex
from setup_env import from_state_file,from_elf_file
import claripy
import re
import sys
import time
from pathlib import Path
import argparse
from config import *
from inifinite_loop_check import *
from angr import exploration_techniques

config = Configs()
stack_size = 0x1000


class ACCESS_INFO:
    def __init__(self):
        pass
    def __eq__(self, other):
        if self.addr == other.addr and self.type == other.type:
            return True
        else:
            return False
    def __hash__(self):
        return hash(hex(self.addr) + hex(self.size))
    
class IRQ_MODEL:
    def __init__(self):
        self.irq = 0
        self.accesses = set()
    def dump(self):
        print("-{}".format(self.irq))
        for access in self.accesses:
            print("{} {}".format(hex(access.addr), hex(access.size)))

def irq_model_from_file(modelfilename):
    models = {}
    model = None
    current_irq = 0
    if not Path(modelfilename).exists():
        return models
    with open(modelfilename, "r") as f:
        for line in f.readlines():
            if "-" in line:
                model = IRQ_MODEL()
                current_irq = int(line[1:])
                models[current_irq] = model
            else:
                accessinfo = ACCESS_INFO()
                accessinfo.type = line.split(":")[0]
                accessinfo.addr = int(line.split(":")[1].split(" ")[0],16)
                accessinfo.size = int(line.split(":")[1].split(" ")[1],16)
                models[current_irq].accesses.add(accessinfo)
    return models
                

def write_model_to_file(models,modelfilename):
    with open(modelfilename, "w") as f:
        for irq,model in models.items():
            f.write("-{}\n".format(irq))
            f.write("".join(["{}:{} {}\n".format(access.type,hex(access.addr),hex(access.size)) for access in model.accesses]))
            


symbolic_mem_data = set()
symbolic_mem_data_addr_mapping = dict()
func_pointer_init_mem = set()

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
    return addr >= stack_top and addr <= stack_base

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
                
def is_ast_value_pointer(state,value):
    try:
        data = state.solver.eval_one(value)
    except Exception as e:
        return False
    return is_pointer(data)

def is_readonly_addr(state,addr):
    for mem in config.mems:
        if addr >= mem.start and addr <= mem.start + mem.size:
            if mem.isreadonly:
                return True
            else:
                return False
    return False

def is_ast_addr_readonly(state,addr):
    try:
        addr = state.solver.eval_one(addr)
    except Exception as e:
        return False
    return is_readonly_addr(state,addr)

def is_addr_valid(addr):
    for mem in config.mems:
        if addr >= mem.start and addr <= mem.start + mem.size:
            return True
    return False
def is_ast_addr_valid(state,addr):
    try:
        addr = state.solver.eval_one(addr)
    except Exception as e:
        return False
    return is_addr_valid(addr)

def is_addr_zero(addr):
    return addr == 0

def is_ast_addr_zero(state,addr):
    try:
        addr = state.solver.eval_one(addr)
    except Exception as e:
        return False
    return is_addr_zero(addr)


def mem_read_before(state):
    try:
        address = state.solver.eval_one(state.inspect.mem_read_address)
    except Exception as e:
        return
    if not is_ast_addr_valid(state,address):
        return
    if is_ast_mmio_address(state, state.inspect.mem_read_address) or is_ast_stack_address(state,state.inspect.mem_read_address):
        return
    value = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')
    if value.symbolic:
        return
    if (is_ast_value_pointer(state,value) and not is_ast_addr_zero(state,value)) or is_ast_mmio_address(state, value):
        return
    if address in symbolic_mem_data:
        return
    symbolic_mem_data.add(address)
    tmp = claripy.BVS(f"mem_sym_{hex(address)}", state.inspect.mem_read_length * 8)
    state.memory.store(address,tmp,disable_actions=True,inspect=False,endness='Iend_LE')
    symbolic_mem_data_addr_mapping[tmp] = address


def mem_read_after(state):
    if not state.inspect.mem_read_expr.symbolic:
        return
    state.inspect.mem_read_expr.is_mmio_access = False
    try:
        address = state.solver.eval_one(state.inspect.mem_read_address)
    except Exception as e:
        return
    if is_ast_mmio_address(state, address):
        state.inspect.mem_read_expr.is_mmio_access = True

def call_after(state):
    if state.inspect.function_address.get_bytes(0,4) in symbolic_mem_data_addr_mapping:
        func_pointer_init_mem.add(symbolic_mem_data_addr_mapping[state.inspect.function_address.get_bytes(0,4)])


def mem_write_before(state):
    pass
def mem_write_after(state):
    pass


def is_memory_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem'

def is_memory_read_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'read'

def is_memory_write_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'write'


def get_memory_access(states,initial_state,accessses,irq):
    has_mmio_read_op = False
    if int(irq,16) == 0xf:
        has_mmio_read_op = True
    for state in states:
        for action in state.history.actions:
            if not is_memory_action(action):
                continue
            if is_ast_stack_address(initial_state,action.addr):
                continue
            if is_ast_addr_readonly(state,action.addr):
                continue
            # print(action)
            if is_ast_mmio_address(state,action.addr) and is_memory_read_action(action):
                has_mmio_read_op = True
            
            if is_ast_mmio_address(state,action.addr):
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mmio"
                accessses.append(info)
                continue
            if not action.addr.symbolic and is_ast_addr_valid(state,action.addr) and is_memory_write_action(action):
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mem"
                accessses.append(info)
                
    return has_mmio_read_op
    

    

def main():
    parser = argparse.ArgumentParser(description="dataflow modeling",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--state", help="irq state binary file")
    parser.add_argument("-i", "--irq",  help="irq number")
    parser.add_argument("-o", "--output", help="output file name")
    parser.add_argument("-c","--config",  help="fuzzware config file")
    parser.add_argument("-m","--mode",  help="irq/loop mode")
    args = parser.parse_args()
    config.from_fuzzware_config_file(args.config)
    

    project, initial_state = from_state_file(args.state,config,args.irq,args.mode == "loop")
    if args.mode == "loop":
        loop_addrs = find_all_infinite_loop(project, initial_state,config)
        with open(args.output,"w") as f:
            for addr in loop_addrs:
                f.write("%x\n"%(addr))
        return
    models = irq_model_from_file(args.output)

    model = IRQ_MODEL()
    if int(args.irq,16) in models:
        model = models[int(args.irq,16)]
    accessses = []
    initial_state.inspect.b("mem_read",when=angr.BP_BEFORE, action=mem_read_before)
    initial_state.inspect.b("call",when=angr.BP_AFTER, action=call_after)
    has_mmio_read_op = False
    simgr = project.factory.simgr(initial_state)
    simgr.use_technique(exploration_techniques.Timeout(2*60))
    for i in range(100):
        simgr.step(thumb=True)
        if len(simgr.active) <= 1 and i >= 10:
            break
        
        get_memory_access(simgr.active + simgr.deadended + simgr.unconstrained + simgr.unsat + simgr.pruned,initial_state,accessses,args.irq)
    # if not has_mmio_read_op:
    #     print("clear cear clear lear")
    #     accessses = []
    for func in func_pointer_init_mem:
        for ac in accessses:
            if ac.addr == func:
                accessses.remove(ac)
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = func
        access.size = 4
        access.type = "func"
        accessses.append(access)
    for ac in accessses:
            model.accesses.add(ac)
    models[int(args.irq,16)] = model

    write_model_to_file(models,args.output)
    

if __name__ == '__main__':
    main()
            
    
    
