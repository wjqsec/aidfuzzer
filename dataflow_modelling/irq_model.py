import angr, monkeyhex
from setup_env import from_state_file,from_elf_file
import claripy
import re
import sys
import time
from pathlib import Path
import argparse
from config import *
from angr import exploration_techniques

config = Configs()
stack_size = 0x2000


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

zero_symbolic_mem_data = set()

nullptr_func_check_mem = set()
nullptr_data_access_check_mem = set()

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
    if is_ast_value_pointer(state,value) or is_ast_mmio_address(state, value):
        return
    if address in symbolic_mem_data:
        return
    tmp = claripy.BVS(f"mem_sym_{hex(address)}", state.inspect.mem_read_length * 8)
    if is_ast_addr_zero(state,value):
        # constrain = tmp == claripy.BVV(0, state.inspect.mem_read_length * 8)
        # state.add_constraints(constrain)
        zero_symbolic_mem_data.add(tmp)
    symbolic_mem_data.add(address)
    state.memory.store(address,tmp,disable_actions=True,inspect=False,endness='Iend_LE')
    symbolic_mem_data_addr_mapping[tmp] = address


def is_accessing_nullptr(state,addr):
    if is_ast_value_pointer(state,addr) or is_ast_mmio_address(state, addr):
        return None
    if isinstance(addr, claripy.ast.Base):
        for ist in addr.leaf_asts():
            if ist in zero_symbolic_mem_data:
                return ist

    return None
    

def mem_read_after(state):
    ist = is_accessing_nullptr(state, state.inspect.mem_read_address)
    if ist == None:
        return
    
    if state.inspect.mem_read_condition.is_true():
        nullptr_data_access_check_mem.add(symbolic_mem_data_addr_mapping[ist])

        
def mem_write_after(state):
    ist = is_accessing_nullptr(state, state.inspect.mem_write_address)
    if ist == None:
        return
    if state.inspect.mem_write_condition.is_true():
        nullptr_data_access_check_mem.add(symbolic_mem_data_addr_mapping[ist])


def call_before(state):
    if state.inspect.function_address.get_bytes(0,4) in zero_symbolic_mem_data:
        nullptr_func_check_mem.add(symbolic_mem_data_addr_mapping[state.inspect.function_address.get_bytes(0,4)])


def mem_write_before(state):
    pass



def is_memory_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem'

def is_memory_read_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'read'

def is_memory_write_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'write'


def get_memory_access(states,initial_state,accessses,irq):
    for state in states:
        for action in state.history.actions:
            # print(action.type,action.ins_addr)
            if not is_memory_action(action):
                continue
            
            if is_ast_stack_address(initial_state,action.addr):
                continue
            
            if is_ast_addr_readonly(state,action.addr):
                continue

            # print(action)
            if is_ast_mmio_address(state,action.addr) and is_memory_read_action(action):
                pass
            
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
                

    

    

def main():
    parser = argparse.ArgumentParser(description="irq dataflow modeling",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--state", help="irq state binary file")
    parser.add_argument("-i", "--irq",  help="irq number")
    parser.add_argument("-v", "--vecbase",  help="vecbase")
    parser.add_argument("-o", "--output", help="output file name")
    parser.add_argument("-c","--config",  help="fuzzware config file")

    args = parser.parse_args()
    config.from_fuzzware_config_file(args.config)
    

    project, initial_state = from_state_file(args.state)

    start_addr = int(args.vecbase,16) + 4 * int(args.irq,10)
    irq_val = initial_state.memory.load(start_addr, 4, endness='Iend_LE')
    initial_state.regs.pc = irq_val
    

    models = irq_model_from_file(args.output)

    
    cfg = project.analyses.CFGFast(normalize = True)
    model = IRQ_MODEL()
    # if int(args.irq,16) in models:
    #     model = models[int(args.irq,16)]
    accessses = []
    initial_state.inspect.b("mem_read",when=angr.BP_BEFORE, action=mem_read_before)
    initial_state.inspect.b("mem_read",when=angr.BP_AFTER, action=mem_read_after)
    initial_state.inspect.b("call",when=angr.BP_BEFORE, action=call_before)

    simgr = project.factory.simgr(initial_state)
    # simgr.use_technique(exploration_techniques.Timeout(30))
    simgr.use_technique(exploration_techniques.LoopSeer(cfg=cfg, bound=10))

    try:
        for i in range(20):
            simgr.step(thumb=True)
            print(simgr.active)
            get_memory_access(simgr.active + simgr.deadended + simgr.unconstrained + simgr.unsat + simgr.pruned,initial_state,accessses,args.irq)
            if len(simgr.active) <= 1 and i >= 10:
                break   
    except :
        print("error happends")
        pass
        
        

    for ptr in nullptr_func_check_mem:
        for ac in accessses:
            if ac.addr == ptr:
                accessses.remove(ac)
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = ptr
        access.size = 4
        access.type = "func"
        accessses.append(access)

    for ptr in nullptr_data_access_check_mem:
        for ac in accessses:
            if ac.addr == ptr:
                accessses.remove(ac)
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = ptr
        access.size = 4
        access.type = "dependency"
        accessses.append(access)
    for ac in accessses:
            model.accesses.add(ac)
    models[int(args.irq,10)] = model

    write_model_to_file(models,args.output)
    

if __name__ == '__main__':
    main()
            
    
    
