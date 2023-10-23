
import re
from io import BytesIO
import angr
import claripy
import argparse
from config import *

state_snapshot_reg_list = ['r0', 'r1', 'r2', 'r3', 'r4',
        'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'lr', 'pc',
        'sp', 'xpsr']

scope_reg_names = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r10', 'r11', 'r12', 'lr', 'sp', 'pc')

regular_register_names = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'lr', 'sp')

newly_added_constraints_reg_names = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r10', 'r11', 'r12', 'lr')

REG_NAME_PC = 'pc'
REG_NAME_SP = 'sp'



reg_regex = re.compile(r"^[^=]{2,4}=0x([0-9a-f]+)$")

def translate_reg_name_to_vex_internal_name(name):
    name = name.lower()

    if name == 'xpsr':
        name = 'cc_dep1'

    return name


def from_elf_file(elf_file):
    project = angr.Project(elf_file)
    initial_state = project.factory.blank_state() 

def from_state_file(statefile):
        
        with open(statefile, "r") as state_file:
            regs = {}

            for name in state_snapshot_reg_list:
                line = state_file.readline()
                val = int(reg_regex.match(line).group(1), 16)
                name = translate_reg_name_to_vex_internal_name(name)
                regs[name] = val

            line = ""
            while line == "":
                line = state_file.readline()

            sio = BytesIO(line.encode()+state_file.read().encode())


        project = angr.Project(sio, arch="ARMCortexM", main_opts={'backend': 'hex'})

        # We need the following option in order for CBZ to not screw us over
        project.factory.default_engine.default_strict_block_end = True

        initial_state = project.factory.call_state(addr=0,add_options=angr.options.refs)

        # arm_thumb_quirks.add_special_initstate_reg_vals(initial_state, regs) maybe later

        # apply registers to state
        for name, val in regs.items():
            ast = claripy.BVS(f"initstate_{name}", 32)  
            if name == "sp":
                constraint = ast == 0x70000000
                initial_state.add_constraints(constraint)
            setattr(initial_state.regs, name, ast)
            

        
        return project,initial_state 




