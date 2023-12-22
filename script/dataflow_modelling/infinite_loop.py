import angr
import capstone
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

project = None
has_conbr = False
config = Configs()

def is_infinite_loop(project,initial_state,addr):
    global has_conbr
    has_conbr = False
    initial_state.regs.pc = addr
    bbl_addr = None
    simgr = project.factory.simgr(initial_state)
    simgr.use_technique(angr.exploration_techniques.Timeout(timeout=5))
    simgr.step(thumb=True,num_inst = 5)
    if len(simgr.active) != 1 or simgr.active[0].regs.pc.symbolic:
            return False,bbl_addr
    init_state = simgr.active[0]

    bbl_addr = init_state.solver.eval_one(init_state.regs.pc) & 0xfffffffe

    for i in range(5):
        simgr.step(thumb=True,num_inst = 5)
        if has_conbr:
            return False,bbl_addr
        if len(simgr.active) != 1:
            return False,bbl_addr
        
        active_state = simgr.active[0]
        bbl_pc = active_state.solver.eval_one(active_state.regs.pc) & 0xfffffffe
        if bbl_pc == bbl_addr:
            return True,bbl_addr
        
    return False,bbl_addr
    

def find_all_infinite_loop(project, initial_state,global_cfg):
    all_loops = set()

    
    memseg = global_cfg.get_memseg_by_name("text")

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
    for i in range(0,memseg.size,2):
        disassembly_block = project.factory.block(memseg.start + i, size=4)
        instruction_bytes = disassembly_block.bytes
        
        for insn in md.disasm(instruction_bytes, memseg.start + i):
            if "b" == insn.mnemonic and "lr" not in insn.op_str:
                print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
                is_loop,bbl_addr = is_infinite_loop(project,initial_state,memseg.start + i)
                if is_loop:
                    all_loops.add(bbl_addr)
            break

                    
    return all_loops


def condbr(state):
    global project
    global has_conbr
    len_ = 4
    try:
        pc_addr = state.solver.eval_one(state.regs.pc)
        disassembly_block = project.factory.block(pc_addr, size=len_).bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB+capstone.CS_MODE_MCLASS)
        inses = md.disasm(disassembly_block, pc_addr)
        for ins in inses:
            if "b" in ins.mnemonic and "b" != ins.mnemonic:
                has_conbr = True
                # setattr(state, name, ast)
                # print( getattr(state.regs, ins.op_str.split(",")[0]))
                # setattr(state.regs,ins.op_str.split(",")[0],state.solver.BVS(f"mrs", 32))
                # print("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
            break

    except Exception as e:
        pass
    pass

if __name__ == "__main__":
    start_time = time.time()
    parser = argparse.ArgumentParser(description="infinite loop modelling",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--state", help="irq state binary file")
    parser.add_argument("-o", "--output", help="output file name")
    parser.add_argument("-c","--config",  help="fuzzware config file")
    args = parser.parse_args()
    config.from_fuzzware_config_file(args.config)  
    project, initial_state = from_state_file(args.state)
    initial_state.inspect.b("instruction",when=angr.BP_BEFORE, action=condbr)
    loop_addrs = find_all_infinite_loop(project, initial_state,config)
    with open(args.output,"w") as f:
        for addr in loop_addrs:
            f.write("%x\n"%(addr))
    end_time = time.time()
    print("infinite total time: {}".format(end_time-start_time))