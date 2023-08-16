import angr
import capstone


def is_infinite_loop(project,initial_state,addr,isthumb):
    initial_state.regs.pc = addr
    bbl_addr = None
    simgr = project.factory.simgr(initial_state)
    simgr.step(thumb=isthumb)
    if len(simgr.active) != 1:
            return False,bbl_addr
    init_state = simgr.active[0]

    bbl_addr = init_state.solver.eval_one(init_state.regs.pc) & 0xfffffffe

    for i in range(5):
        simgr.step(thumb=isthumb)
        if len(simgr.active + simgr.deadended + simgr.unconstrained) > 1 or len(simgr.active) != 1:
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

        
