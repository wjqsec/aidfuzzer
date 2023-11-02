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

config = Configs()
stack_size = 0x2000
fix_lr = 0xdeadbeef

project = None
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
        self.toend = False
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
                current_irq = int(line.split("-")[1].split("-")[0])
                models[current_irq] = model
                if "y" in line:
                    model.toend = True
                else:
                    model.toend = False
            else:
                accessinfo = ACCESS_INFO()
                accessinfo.type = line.split(":")[0]
                accessinfo.addr = int(line.split(":")[1].split(" ")[0],16)
                accessinfo.size = int(line.split(":")[1].split(" ")[1],16)
                models[current_irq].accesses.add(accessinfo)
    return models
                

def write_model_to_file(models,modelfilename):
    toend_str = ""
    with open(modelfilename, "w") as f:
        for irq,model in models.items():
            if model.toend:
                toend_str = "y"
            else:
                toend_str = "n"
            f.write("-{}-{}\n".format(irq,toend_str))
            f.write("".join(["{}:{} {}\n".format(access.type,hex(access.addr),hex(access.size)) for access in model.accesses]))
            


symbolic_mem_data = set()
symbolic_mem_data_addr_mapping = dict()
symbolic_mem_data_addr_mapping_rev = dict()

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
        if addr >= mem.start and addr <= mem.start + mem.size and mem.start != 0:
            if mem.ismmio:
                return False
            else:
                return True
    return False
                
def is_ast_pointer(state,value):
    try:
        data = state.solver.eval_one(value)
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

def is_ast_readonly(state,addr):
    try:
        addr = state.solver.eval_one(addr)
    except Exception as e:
        return False
    return is_readonly(state,addr)


def is_zero(addr):
    return addr == 0

def is_ast_zero(state,addr):
    try:
        addr = state.solver.eval_one(addr)
    except Exception as e:
        return False
    return is_zero(addr)

def is_ast_contains_zero_ptr(addr):
    for leaf in addr.leaf_asts():    
        if leaf in zero_symbolic_mem_data:
            return True
    return False

def get_parent_zero_ast(addr):
    for leaf in addr.leaf_asts():    
        if leaf in zero_symbolic_mem_data:
            return symbolic_mem_data_addr_mapping[leaf]

def get_final_pointer(addr):
    while True:
        ptr = symbolic_mem_data_addr_mapping[addr]
        if not ptr in symbolic_mem_data_addr_mapping:
            return ptr
        addr = ptr


def ast_cannot_be_zero(state,ast):
    state_backup = state.copy()

    state_backup.add_constraints(ast == 0)
    ret = state_backup.satisfiable()

    state_backup.solver.constraints.pop()
    state_backup.solver.reload_solver()

    return not ret




def mem_read_before(state):

    addr = state.inspect.mem_read_address
    if type(addr) is tuple:
        addr = addr[1]
    try:
        address = state.solver.eval_one(addr)
    except Exception as e:
        return
            
        
    
    if not is_ast_pointer(state,addr):
        return
    if is_ast_stack_address(state,addr):
        return
    value = state.memory.load(address, state.inspect.mem_read_length,disable_actions=True,inspect=False, endness='Iend_LE')
    try:
        value = state.solver.eval_one(value)
    except Exception as e:
        return


    if is_ast_pointer(state,value) or is_ast_mmio_address(state, value):
        return
    
    if address in symbolic_mem_data:
        state.memory.store(address,symbolic_mem_data_addr_mapping_rev[address],disable_actions=True,inspect=False,endness='Iend_LE')
        return
    
    tmp = state.solver.BVS(f"mem_sym_{hex(address)}", state.inspect.mem_read_length * 8)


    if is_ast_zero(state,value):
        zero_symbolic_mem_data.add(tmp)


    
    # print("replace ",hex(address))
    
    state.memory.store(address,tmp,disable_actions=True,inspect=False,endness='Iend_LE')
    symbolic_mem_data_addr_mapping[tmp] = address
    symbolic_mem_data_addr_mapping_rev[address] = tmp
    symbolic_mem_data.add(address)

   

def mem_read_after(state):
    
    addr = state,state.inspect.mem_read_address
    value = state,state.inspect.mem_read_expr

    if type(addr) is tuple:
        addr = addr[1]
    if type(value) is tuple:
        value = value[1]

    if ast_cannot_be_zero(state,addr) and not is_ast_contains_zero_ptr(addr):
        return

    if is_ast_contains_zero_ptr(addr):
        zero_symbolic_mem_data.add(addr)
        symbolic_mem_data_addr_mapping[addr] = get_parent_zero_ast(addr)


        zero_symbolic_mem_data.add(value)
        symbolic_mem_data_addr_mapping[value] = get_parent_zero_ast(addr)


    if addr in zero_symbolic_mem_data:
        # print(state.regs.pc,get_final_pointer(addr))
        nullptr_data_access_check_mem.add(get_final_pointer(addr))

        
def mem_write_after(state):

    addr = state,state.inspect.mem_write_address
    if type(addr) is tuple:
        addr = addr[1]
    if ast_cannot_be_zero(state,addr) and not is_ast_contains_zero_ptr(addr):
        return
    if addr in zero_symbolic_mem_data:
        # print(state.regs.pc,get_final_pointer(addr))
        nullptr_data_access_check_mem.add(get_final_pointer(addr))

def call_before(state):
    addr = state.inspect.function_address.get_bytes(0,4)
    if type(addr) is tuple:
        addr = addr[1]
    if addr in zero_symbolic_mem_data:
        nullptr_func_check_mem.add(get_final_pointer(addr))
        if not ast_cannot_be_zero(state,addr):
            # print(state.regs.pc,get_final_pointer(addr))
            nullptr_data_access_check_mem.add(get_final_pointer(addr))


def mrs_write_after(state):
    global project
    len_ = 4
    try:
        pc_addr = state.solver.eval_one(state.regs.pc)
        disassembly_block = project.factory.block(pc_addr, size=len_).bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
        inses = md.disasm(disassembly_block, pc_addr)
        for ins in inses:
            if ins.mnemonic == "mrs":
                # setattr(state, name, ast)
                # print( getattr(state.regs, ins.op_str.split(",")[0]))
                setattr(state.regs,ins.op_str.split(",")[0],state.solver.BVS(f"mrs", 32))
                pass
                # print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
            break

        # if pc_addr == 0xD1Ff:
            # state.regs.r0 = 2
            # print(state.inspect.reg_write_offset,state.inspect.reg_write_expr)
    except Exception as e:
        pass



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
            
            if not is_memory_action(action):
                continue

            
            if is_ast_stack_address(initial_state,action.addr):
                continue
            
            # print(action)
            if is_ast_readonly(state,action.addr):
                continue
            
            if is_memory_read_action(action):
                continue

            if is_ast_zero(state,action.addr):
                continue


            if is_ast_mmio_address(state,action.addr):
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)
                info.size = int((action.size + 0)/8)
                info.type = "mmio"
                accessses.append(info)
            if not action.addr.symbolic and is_ast_pointer(state,action.addr) and is_memory_write_action(action):
                info = ACCESS_INFO()
                info.ins_addr = state.solver.eval_one(action.ins_addr)
                info.addr = state.solver.min(action.addr)

                info.size = int((action.size + 0)/8)
                info.type = "mem"
                accessses.append(info)
                

    
def collect_pcs(pcs, states):
    for state in states:
        try:
            pc_addr = state.solver.eval_one(state.regs.pc)
            pcs.add(pc_addr)
        except Exception as e:
            pass
        
    

def main():
    global project
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
    initial_state.regs.lr = fix_lr

    models = irq_model_from_file(args.output)
    print("start pc:  ",irq_val)

    model = IRQ_MODEL()
    # if int(args.irq,16) in models:
    #     model = models[int(args.irq,16)]
    accessses = []
    initial_state.inspect.b("mem_read",when=angr.BP_BEFORE, action=mem_read_before)
    initial_state.inspect.b("mem_read",when=angr.BP_AFTER, action=mem_read_after)
    initial_state.inspect.b("mem_write",when=angr.BP_BEFORE, action=mem_write_before)
    initial_state.inspect.b("call",when=angr.BP_BEFORE, action=call_before)
    initial_state.inspect.b("instruction",when=angr.BP_AFTER, action=mrs_write_after)

    
    



    simgr = project.factory.simgr(initial_state)

    # simgr.use_technique(exploration_techniques.Timeout(20))
    
    
    

    
    pcs = set()
    


    collect_pcs(pcs, simgr.active)
    last_num_pcs = len(pcs)


    while True:
        simgr.step(thumb=True)
        get_memory_access(simgr.active,initial_state,accessses,args.irq)
        
        print(simgr.active)

        for ac in simgr.active:
            try:
                pc_addr = ac.solver.eval_one(ac.regs.pc)
                if pc_addr == fix_lr:
                    model.toend = True
            except Exception as e:
                pass
            
        collect_pcs(pcs, simgr.active)
        if last_num_pcs == len(pcs):
            break
        else:
            last_num_pcs = len(pcs)
            
        
        # print("-----------------------")


        

    for ptr in nullptr_func_check_mem:
        access = ACCESS_INFO()
        access.ins_addr = 0
        access.addr = ptr
        access.size = 4
        access.type = "func"
        accessses.append(access)

    for ptr in nullptr_data_access_check_mem:
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
            
    
    
