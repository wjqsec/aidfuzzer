import angr, monkeyhex
from setup_env import from_state_file
import claripy
import re
import sys
import time
from pathlib import Path
import argparse
from config import *
from inifinite_loop_check import *


config = Configs()
stack_size = 0x4000


class ACCESS_INFO:
    def __init__(self):
        pass
    def __eq__(self, other):
        if self.addr == other.addr and self.size==other.size:
            return True
        else:
            return False
    def __hash__(self):
        return hash(hex(self.addr) + hex(self.size))
    
class IRQ_MODEL:
    def __init__(self):
        self.irq = 0
        self.accesses = []
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
                models[current_irq].accesses.append(accessinfo)
    return models
                

def write_model_to_file(models,modelfilename):
    with open(modelfilename, "w") as f:
        for irq,model in models.items():
            f.write("-{}\n".format(irq))
            f.write("".join(["{}:{} {}\n".format(access.type,hex(access.addr),hex(access.size)) for access in model.accesses]))
            





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


def is_pointer(state,addr):
    for mem in config.mems:
        if addr >= mem.start and addr <= mem.start + mem.size:
            if mem.ismmio:
                return False
            else:
                return True
    return False
                
        

def is_ast_value_pointer(state,value):
    try:
        addr = state.solver.eval_one(value)
    except Exception as e:
        return False
    return is_pointer(state,addr)

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
'''
def mem_read_before(state):
    try:
        address = state.solver.eval_one(state.inspect.mem_read_address)
    except Exception as e:
        return
    if is_ast_mmio_address(state, state.inspect.mem_read_address) or is_ast_stack_address(state,state.inspect.mem_read_address):
        return
    value = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')
    if value.symbolic:
        return
    if is_ast_value_pointer(state,value) or is_ast_mmio_address(state, value):
        pass
    else:
        # print(state.inspect.mem_read_address)
        # print(value)
        state.memory.store(address,claripy.BVS(f"mem_sym_{hex(address)}", state.inspect.mem_read_length * 8),disable_actions=True,inspect=False)

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
    
def mem_write_before(state):
    pass
def mem_write_after(state):
    pass
'''

def is_memory_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem'

def is_memory_read_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'read'

def is_memory_write_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'write'




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
    models = irq_model_from_file(args.output)

    project, initial_state = from_state_file(args.state,config,args.irq)
    if args.mode == "loop":
        loop_addrs = find_all_infinite_loop(project, initial_state,config)
        with open(args.output,"w") as f:
            for addr in loop_addrs:
                f.write("%x\n"%(addr))
        return
    
    simgr = project.factory.simgr(initial_state)
    for i in range(200):
        if i == 20 and len(simgr.active + simgr.deadended + simgr.unconstrained) <= 1:
            break
        simgr.step(thumb=True)
    states = simgr.active + simgr.deadended + simgr.unconstrained
    model = IRQ_MODEL()
    accessses = []
    for state in states:
        access = []
        for action in state.history.actions:
            if not is_memory_action(action):
                continue
            if is_ast_stack_address(initial_state,action.addr):
                continue
            
            if is_ast_addr_readonly(state,action.addr):
                continue
            
            if is_ast_mmio_address(state,action.addr):
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mmio"
                access.append(info)
            if not action.addr.symbolic:
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mem"
                access.append(info)
                
        if access == []:   
            continue 
        accessses.append(access)

    tmp = set()
    for ac in accessses:
        for info in ac:
            tmp.add(info)
    model.accesses = [x for x in tmp]
    models[int(args.irq,16)] = model
    write_model_to_file(models,args.output)

if __name__ == '__main__':
    main()
            
    
    
