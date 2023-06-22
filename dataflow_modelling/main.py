import angr, monkeyhex
from setup_env import from_state_file
import claripy
import re
import sys
import time
from pathlib import Path
stack_size = 0x4000

MAX_ACTIVE_STATES = 100

MAX_DEAD_VARS = 3
MAX_STATES = 20
MAX_CALL_DEPTH = 2
MAX_BB_VISITS = 5
NON_FORKING_STATE_MAX_BB_VISITS = 50

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
                accessinfo.addr = int(line.split(" ")[0],16)
                accessinfo.size = int(line.split(" ")[1],16)
                models[current_irq].accesses.append(accessinfo)
    return models
                

def write_model_to_file(models,modelfilename):
    with open(modelfilename, "w") as f:
        for irq,model in models.items():
            f.write("-{}\n".format(irq))
            f.write("".join(["{} {}\n".format(hex(access.addr),hex(access.size)) for access in model.accesses]))
            





def is_mmio_address(state, addr):
    return addr >= 0x40000000 and addr <= 0x50000000

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
    return (addr >= 0x20000000 and addr <= 0x20020000) or (addr >= 0x8000000 and addr <= 0x8017000)

def is_ast_value_pointer(state,value):
    try:
        addr = state.solver.eval_one(value)
    except Exception as e:
        return False
    return is_pointer(state,addr)

def is_readonly_addr(state,addr):
    return addr >= 0x8000000 and addr <= 0x8044000

def is_ast_addr_readonly(state,addr):
    try:
        addr = state.solver.eval_one(addr)
    except Exception as e:
        return False
    return is_readonly_addr(state,addr)

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


def is_memory_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem'

def is_memory_read_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'read'

def is_memory_write_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'write'



if(len(sys.argv) < 4):
    print("args error")
    exit(0)

models = irq_model_from_file(sys.argv[2])

project, initial_state, cfg = from_state_file(sys.argv[1],None,sys.argv[3])


# initial_state.inspect.b('mem_read',when=angr.BP_BEFORE,action=mem_read_before)
# initial_state.inspect.b('mem_read',when=angr.BP_AFTER,action=mem_read_after)
# initial_state.inspect.b('mem_write',when=angr.BP_BEFORE,action=mem_write_before)
# initial_state.inspect.b('mem_write',when=angr.BP_AFTER,action=mem_write_after)


simgr = project.factory.simgr(initial_state)



# simgr.use_technique(TimeoutDetector(1000))
# simgr.use_technique(LoopEscaper())
# simgr.use_technique(StateExplosionDetector())

for i in range(300):
    if i == 30 and len(simgr.active + simgr.deadended + simgr.unconstrained) <= 1:
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
        if is_ast_mmio_address(state,action.addr):
            continue
        if is_ast_addr_readonly(state,action.addr):
            continue

        if not action.addr.symbolic:
            info = ACCESS_INFO()
            info.ins_addr = state.solver.eval_one(action.ins_addr)
            info.addr = state.solver.min(action.addr)
            info.size = int((action.size + 0)/8)
            access.append(info)
            
    if access == []:   
        continue 
    accessses.append(access)

tmp = set()
for ac in accessses:
    for info in ac:
        tmp.add(info)
model.accesses = [x for x in tmp]
models[int(sys.argv[3],16)] = model
write_model_to_file(models,sys.argv[2])



        
    
            
    
    
