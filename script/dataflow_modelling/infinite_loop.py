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

config = Configs()

def is_infinite_loop(project,initial_state,addr):
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="infinite loop modelling",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--state", help="irq state binary file")
    parser.add_argument("-o", "--output", help="output file name")
    parser.add_argument("-c","--config",  help="fuzzware config file")
    args = parser.parse_args()
    config.from_fuzzware_config_file(args.config)  
    project, initial_state = from_state_file(args.state)
    loop_addrs = find_all_infinite_loop(project, initial_state,config)
    with open(args.output,"w") as f:
        for addr in loop_addrs:
            f.write("%x\n"%(addr))