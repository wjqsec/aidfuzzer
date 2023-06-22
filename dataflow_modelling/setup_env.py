
import re
from io import BytesIO
import angr
import claripy
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


global_cfg = {      "vecbase" : 0x8000000,
                    "mmio1" : {
                        "type" : "mmio",
                        "start" : 0x20000000,
                        "len"   : 0x20000000
} 
              }
def parse_cfg_file(cfgfile):
    return global_cfg

def from_state_file(statefile, cfgfile,irq):
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

        irq_addr = global_cfg["vecbase"] + int(irq,16) * 4
        project = angr.Project(sio, arch="ARMCortexM", main_opts={'backend': 'hex'})
        emptry_state = project.factory.entry_state()
        irq_val = emptry_state.memory.load(irq_addr, 4, endness='Iend_LE')

        print(irq_val)
        # We need the following option in order for CBZ to not screw us over
        project.factory.default_engine.default_strict_block_end = True

        initial_state = project.factory.call_state(addr=irq_val,add_options=angr.options.refs)

        # arm_thumb_quirks.add_special_initstate_reg_vals(initial_state, regs) maybe later

        # apply registers to state
        initial_sp = None
        for name, val in regs.items():
            if name == 'lr':
                initial_state.regs.lr = claripy.BVS(f"initstate_{name}", 32)
                continue
            if name == "pc":
                continue
            ast = claripy.BVS(f"initstate_{name}", 32)
            bitvecval = claripy.BVV(val, 32)
            constraint = ast == bitvecval
            initial_state.add_constraints(constraint)

            setattr(initial_state.regs, name, ast)

        
        return project, initial_state, parse_cfg_file(cfgfile)

# def from_elf_file(elffile,cfgfile):
#     project = angr.Project(elffile)
#     initial_state = project.factory.call_state(0x8001D04,add_options=angr.options.refs)

