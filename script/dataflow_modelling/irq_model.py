import angr, monkeyhex
from setup_env import from_state_file,from_elf_file
import claripy
import re
import sys
import capstone
import time
from pathlib import Path
import argparse
from config import *
from angr import exploration_techniques
import pyvex.lifting.gym.arm_spotter
import logging

# logging.getLogger('angr').setLevel('ERROR')

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



nullptr_addresses = set()
null_values = set()
value_addr_map = dict()
value_concrete_value_map = dict()


nullptr_func_check_mem = set()
nullptr_func_check_mem_addr = set()

nullptr_data_access_check_mem = set()
nullptr_data_access_check_mem_addr = set()

mem_access_addr = set()

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

def get_addr_ast_in_ast(ast):
    for leaf in ast.leaf_asts():
        if leaf in value_concrete_value_map:
            return leaf
    return None

def get_nullptr_ast_in_ast(ast):
    if ast in null_values:
        return ast
    ret = None
    for leaf in ast.leaf_asts():    
        if leaf in null_values:
            ret = leaf
        elif leaf.symbolic:
            return None
    
    return ret

def get_addr_for_null_value(ast):
    while True:
        addr = value_addr_map[ast]
        if addr in nullptr_addresses:
            return addr
        ast = addr

def get_ast_len(ast):
    ret = 0
    for leaf in ast.leaf_asts():
        ret += 1
    return ret



def ast_cannot_be_zero(state,ast):
    state_backup = state.copy()

    state_backup.add_constraints(ast == 0)
    ret = state_backup.satisfiable()
    state_backup.solver.constraints.pop()
    state_backup.solver.reload_solver()
    return not ret

def ast_can_be_zero(state,ast):
    return not ast_cannot_be_zero(state,ast)

def ast_condition_hold(state,con):
    state_backup = state.copy()
    state_backup.add_constraints(con)
    ret = state_backup.satisfiable()

    state_backup.solver.constraints.pop()
    state_backup.solver.reload_solver()
    return ret

def mem_read_before(state):

    addr = state.inspect.mem_read_address
    if type(addr) is tuple:
            addr = addr[1]
    root_ast = get_addr_ast_in_ast(addr)
    
    if root_ast != None and value_concrete_value_map[root_ast] != 0:
        state.add_constraints(root_ast == value_concrete_value_map[root_ast])
        state.solver.reload_solver()
        
    try:
        address = state.solver.eval_one(addr)
    except Exception as e:
        return
    
    if not is_ast_pointer(state,address):
        return
    
    if is_ast_stack_address(state,address):
        return
    
    if is_ast_readonly(state,address):
        return
    
    

    if is_ast_mmio_address(state, address):
        state.memory.store(address, state.solver.BVS(f"mmio_sym_{hex(address)}", state.inspect.mem_read_length * 8) ,disable_actions=True,inspect=False,endness='Iend_LE')
        return
    value = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')
    try:
        value = state.solver.eval_one(value)
    except Exception as e:
        return
    
    if is_ast_stack_address(state,value) or is_ast_mmio_address(state, value):
        return

    
    tmp = state.solver.BVS(f"mem_sym_{hex(address)}", state.inspect.mem_read_length * 8)

    state.memory.store(address,tmp,disable_actions=True,inspect=False,endness='Iend_LE')
    
    # if is_ast_zero(state,value) and state.inspect.mem_read_length == 4:
    if state.inspect.mem_read_length == 4 and value == 0:
        nullptr_addresses.add(address)
        null_values.add(tmp)
        value_addr_map[tmp] = address
    value_concrete_value_map[tmp] = value
    


   

def mem_read_after(state):
    
    addr = state,state.inspect.mem_read_address
    value = state,state.inspect.mem_read_expr

    if type(addr) is tuple:
        addr = addr[1]
    if type(value) is tuple:
        value = value[1]


    assign_value = state.solver.BVS(f"assign_sym_{hex(state.addr)}", state.inspect.mem_read_length * 8)
    disassembly_block = project.factory.block(state.addr, size=4).bytes
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
    md.detail = True
    inses = md.disasm(disassembly_block, state.addr)
    for ins in inses:
        if "ldr" not in ins.mnemonic:
            return
        if len(ins.operands) < 2 :
            return
        if "[" not in ins.op_str:
            return
        base_addr_reg = ins.op_str.split("[")[1].split("]")[0]
        if "," in base_addr_reg:
            base_addr_reg = base_addr_reg.split(",")[0]
        if base_addr_reg == "pc":
            return
        # # addr = getattr(state.regs,base_addr_reg)
        # print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
        # print(base_addr_reg)
        # print(addr)
        # print(getattr(state.regs,base_addr_reg))
        

        # nullptr_ast = get_nullptr_ast_in_ast(addr)
        # if nullptr_ast == None:
        #     return
        # setattr(state.regs,ins.op_str.split(",")[0],assign_value)
        break
    nullptr_ast = get_nullptr_ast_in_ast(addr)
    if nullptr_ast == None:
        return

    null_values.add(addr)
    value_addr_map[addr] = get_addr_for_null_value(nullptr_ast)
    # angr read zero from symbolic memory, this is not what we want, replace it with a symbolic value
    
    # state.add_constraints(assign_value == 0)
    null_values.add(assign_value)
    value_addr_map[assign_value] = addr
        
    if ast_cannot_be_zero(state,nullptr_ast) or state.addr in nullptr_data_access_check_mem_addr:
        return
    
    if len(state.solver.constraints) > 5:
        return

    print("add mem_read_after dependency pc ",hex(state.addr), " ast ",addr," addr ",hex(get_addr_for_null_value(nullptr_ast)))
    
    nullptr_data_access_check_mem.add(get_addr_for_null_value(nullptr_ast))
    nullptr_data_access_check_mem_addr.add(state.addr)

        
def mem_write_after(state):
    addr = state,state.inspect.mem_write_address
    if type(addr) is tuple:
        addr = addr[1]
    nullptr_ast = get_nullptr_ast_in_ast(addr)
    if nullptr_ast == None:
        return
    if ast_cannot_be_zero(state,nullptr_ast) or state.addr in nullptr_data_access_check_mem_addr:
        return
    if len(state.solver.constraints) > 5:
        return
    print("add mem_write_after dependency pc ",hex(state.addr), " ast ",addr," addr ",hex(get_addr_for_null_value(nullptr_ast)))
    
    nullptr_data_access_check_mem.add(get_addr_for_null_value(nullptr_ast))
    nullptr_data_access_check_mem_addr.add(state.addr)

def call_before(state):
    return
    # to make the symbol expression simple, we replace the function arguments that contain more than 32 characters with a single symbol.
    # I believe it doesn't affect the evaluation retuslt, becase angr cannot handle too complicated symbols.

    # if state.addr == 0x16b29:
    #     print(state.regs.r0, get_ast_len(state.regs.r0))    
    # if (get_ast_len(state.regs.r0) == 2):
    # state.regs.r0 = state.solver.BVS(f"callr0_sym_{hex(state.addr)}", 32)
    # if (get_ast_len(state.regs.r1) == 2):
    # state.regs.r1 = state.solver.BVS(f"callr0_sym_{hex(state.addr)}", 32)
    # if (get_ast_len(state.regs.r2) == 2):
    # state.regs.r2 = state.solver.BVS(f"callr0_sym_{hex(state.addr)}", 32)
    # if (get_ast_len(state.regs.r3) == 2):
    # state.regs.r3 = state.solver.BVS(f"callr0_sym_{hex(state.addr)}", 32)

    # try:
    #     state.solver.eval_one(state.regs.r0)
    # except Exception as e:
    #     if len(str(state.regs.r0)) > 300:
    #         print("replace call argument r0",state.regs.r0)
    #         state.regs.r0 = state.solver.BVS(f"callr0_sym_{hex(state.addr)}", 32)

    # try:
    #     state.solver.eval_one(state.regs.r1)
    # except Exception as e:
    #     if len(str(state.regs.r1)) > 300:
    #         print("replace call argument r1",state.regs.r1)
    #         state.regs.r1 = state.solver.BVS(f"callr1_sym_{hex(state.addr)}", 32)

    # try:
    #     state.solver.eval_one(state.regs.r2)
    # except Exception as e:
    #     if len(str(state.regs.r2)) > 300:
    #         print("replace call argument r2",state.regs.r2)
    #         state.regs.r2 = state.solver.BVS(f"callr2_sym_{hex(state.addr)}", 32)

    # try:
    #     state.solver.eval_one(state.regs.r3)
    # except Exception as e:
    #     if len(str(state.regs.r3)) > 300:
    #         print("replace call argument r3",state.regs.r3)
    #         state.regs.r3 = state.solver.BVS(f"callr3_sym_{hex(state.addr)}", 32)
    

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
                if addr in value_concrete_value_map and value_concrete_value_map[addr] != 0:
                    print("resolve a function at ",hex(pc_addr), "to pointer ",hex(value_concrete_value_map[addr]))
                    state.add_constraints(addr == value_concrete_value_map[addr])
                    setattr(state.regs,ins.op_str,value_concrete_value_map[addr])
                    state.solver.reload_solver()
                    break

                nullptr_ast = get_nullptr_ast_in_ast(addr)
                if nullptr_ast == None:
                    break
                
                if state.addr not in  nullptr_func_check_mem_addr:
                    nullptr_func_check_mem.add(get_addr_for_null_value(nullptr_ast))
                    nullptr_func_check_mem_addr.add(state.addr)
                    print("add nullptr  pc  ",hex(pc_addr),"  ast  ", nullptr_ast, "  addr   ",hex(get_addr_for_null_value(nullptr_ast)))
                if ast_cannot_be_zero(state,nullptr_ast) or state.addr in nullptr_data_access_check_mem_addr or len(state.solver.constraints) > 5:
                    break
                
                nullptr_data_access_check_mem.add(get_addr_for_null_value(nullptr_ast))
                nullptr_data_access_check_mem_addr.add(state.addr)
                print("add call dependency pc ",hex(pc_addr), " ast ",addr," addr ",hex(get_addr_for_null_value(nullptr_ast)))
    
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
                # setattr(state, name, ast)
                # print( getattr(state.regs, ins.op_str.split(",")[0]))
                setattr(state.regs,ins.op_str.split(",")[0],state.solver.BVS(f"mrs", 32))
                # print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
            break

    except Exception as e:
        pass


def is_memory_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem'

def is_memory_read_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'read'

def is_memory_write_action(action):
    return isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.type == 'mem' and action.action == 'write'




def get_memory_access(states,accessses):
    for state in states:
        for action in state.history.actions:
            
            if not is_memory_action(action):
                continue

            
            if is_ast_stack_address(state,action.addr):
                continue

            # if is_memory_read_action(action) and not is_ast_mmio_address(state,action.addr):
            # print(action)
            # print(state.solver.constraints)
            if is_ast_readonly(state,action.addr):
                continue
            
            if is_memory_read_action(action):
                continue
            if is_ast_zero(state,action.addr):
                continue
            if not is_ast_only_eval_one_value(state,action.addr):
                continue


            if is_ast_mmio_address(state,action.addr):
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mmio"
                accessses.add(info)
            if is_ast_pointer(state,action.addr) and is_memory_write_action(action) and action.ins_addr not in  mem_access_addr:
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mem"
                accessses.add(info)
                mem_access_addr.add(info.ins_addr)
                print("watchpoint",hex(info.ins_addr),hex(info.addr))

                
        
    

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
    suggest = angr.exploration_techniques.Suggestions()
    loopser = angr.exploration_techniques.LocalLoopSeer(bound=1)       
    project, initial_state = from_state_file(args.state)

    start_addr = int(args.vecbase,16) + 4 * int(args.irq,10)
    irq_val = initial_state.memory.load(start_addr, 4, endness='Iend_LE')
    irq_val = initial_state.solver.eval_one(irq_val)
    initial_state.regs.pc = irq_val
    initial_state.regs.lr = fix_lr

    models = irq_model_from_file(args.output)
    model = get_and_insert_model(models,int(args.irq,10),irq_val,int(args.id,16))
    
    print("start pc:  ",hex(irq_val))

    initial_state.inspect.b("mem_read",when=angr.BP_BEFORE, action=mem_read_before)
    initial_state.inspect.b("mem_read",when=angr.BP_AFTER, action=mem_read_after)
    initial_state.inspect.b("call",when=angr.BP_BEFORE, action=call_before)
    initial_state.inspect.b("instruction",when=angr.BP_AFTER, action=mrs_write_after)
    # initial_state.inspect.b("instruction",when=angr.BP_BEFORE, action=call_ins_before)
    initial_state.inspect.b("statement",when=angr.BP_BEFORE, action=call_statement_before)
    
    



    simgr = project.factory.simgr(initial_state)

    simgr.use_technique(spiller)
    # simgr.use_technique(suggest)
    # simgr.use_technique(loopser)
    

    for i in range(50):
        get_memory_access(simgr.active,model.accesses)
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
        
        # print(simgr.active)
        
        
        simgr.step(thumb=True)
        simgr.deadended.clear()
        simgr.unconstrained.clear()
        simgr.pruned.clear()
        simgr.unsat.clear()
        # print("--------------------------",simgr.spill_stage)    

    
    print(model.toend)
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
    print("irq total time: {}".format(end_time-start_time))
    

if __name__ == '__main__':
    main()
            
    
    
