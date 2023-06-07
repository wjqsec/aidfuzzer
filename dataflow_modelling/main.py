import angr, monkeyhex
from setup_env import from_state_file
import claripy
import re


stack_size = 0x4000



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
    return addr >= 0x8000000 and addr <= 0x8017000

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


def contains_all_key(item_one, item_two):
    for k,v in item_one.items():
        if k not in item_two:
            return False
    return len(item_two) > len(item_one) 


project, initial_state, cfg = from_state_file('/home/w/hd/iofuzzer/out/state/state_irq_08001d04',None)


initial_state.inspect.b('mem_read',when=angr.BP_BEFORE,action=mem_read_before)
initial_state.inspect.b('mem_read',when=angr.BP_AFTER,action=mem_read_after)
initial_state.inspect.b('mem_write',when=angr.BP_BEFORE,action=mem_write_before)
initial_state.inspect.b('mem_write',when=angr.BP_AFTER,action=mem_write_after)


simgr = project.factory.simgr(initial_state)


simgr.run(thumb=True)

states = simgr.active + simgr.deadended + simgr.unconstrained

all_access = []
for state in states:
    access = dict()
    # addrs = set()
    print("**************")
    for action in state.history.actions:
        if not is_memory_action(action):
            continue
        if is_ast_stack_address(initial_state,action.addr):
            continue
        if is_ast_mmio_address(state,action.addr):
            continue
        if is_ast_addr_readonly(state,action.addr):
            continue
    #     addrs.add(hex(state.solver.min(action.addr)))
    # print(addrs)
        # if hex(state.solver.min(action.addr)) in addrs:
        #     continue
        # addrs.add(hex(state.solver.min(action.addr)))
        access[hex(state.solver.eval_one(action.ins_addr))] = hex(state.solver.min(action.addr))
        # for guard in state.history.jump_guards:
        #     print()
    
    if access == {}:   
        continue 
    # for k,v in access.items():
    #     print(k,v)
    all_access.append(access)
    print("-------------")

to_delete = []
for ac1 in all_access:
    for ac2 in all_access:
        if ac1 != ac2 and contains_all_key(ac1, ac2):
            to_delete.append(ac1)
for delete in to_delete:
    if delete in all_access:
        all_access.remove(delete)
for ac in all_access:
    print("**************")
    for k,v in ac.items():
        print(k,v)
    print("-------------")
            
    
    
