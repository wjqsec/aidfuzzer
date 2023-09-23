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

def is_infinite_loop(project,initial_state,addr,isthumb):
    initial_state.regs.pc = addr
    bbl_addr = None
    simgr = project.factory.simgr(initial_state)
    simgr.step(thumb=isthumb)
    if len(simgr.active) != 1 or simgr.active[0].regs.pc.symbolic:
            return False,bbl_addr
    init_state = simgr.active[0]

    bbl_addr = init_state.solver.eval_one(init_state.regs.pc) & 0xfffffffe

    for i in range(3):
        simgr.step(thumb=isthumb)
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

    ins_size = 4
    for i in range(0,memseg.size,ins_size):
        disassembly_block = project.factory.block(memseg.start + i, size=ins_size)
        instruction_bytes = disassembly_block.bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        for insn in md.disasm(instruction_bytes, memseg.start + i):
            if "b" == insn.mnemonic:
                is_loop,bbl_addr = is_infinite_loop(project,initial_state,memseg.start + i,ins_size == 2)
                if is_loop:
                    all_loops.add(bbl_addr)
    ins_size = 2
    for i in range(0,memseg.size,ins_size):
        disassembly_block = project.factory.block(memseg.start + i, size=ins_size)
        instruction_bytes = disassembly_block.bytes
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        for insn in md.disasm(instruction_bytes, memseg.start + i):
            if "b" == insn.mnemonic:
                is_loop,bbl_addr = is_infinite_loop(project,initial_state,memseg.start + i,ins_size == 2)
                if is_loop:
                    all_loops.add(bbl_addr)
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