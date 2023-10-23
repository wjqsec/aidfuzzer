



class MemSeg:
    def __init__(self):
        self.ismmio = False
        self.name = ""
        self.start = 0
        self.size = 0
        self.isreadonly = False
        

class Configs:
    def __init__(self):
        self.vecbase = 0
        self.mems = []
    def isreadonly(self):
        return self.isreadonly
    def ismmio(self):
        return self.ismmio
    def get_range(self):
        return self.start,self.start + self.size
    def get_memseg_by_name(self,name):
        for mem in self.mems:
            if name == mem.name:
                return mem
        return None
    def from_fuzzware_config_file(self,config_file):
        memseg = None
        start = False
        with open(config_file,"r") as f:
            while True:
                line = f.readline()
                if len(line) == 0:
                    break
                if line == "" or "symbols:" in line:
                    start = False
                    continue
                if "memory_map:" in line:
                    start = True
                    continue
                if not start:
                    continue
                if line.startswith("  ") and not line.startswith("    "):
                    if memseg != None:
                        self.mems.append(memseg)
                    memseg = MemSeg()
                    if "mmio" in line:
                        memseg.ismmio = True
                    elif "irq_ret" in line or "nvic" in line:
                        memseg = None
                    else:
                        memseg.ismmio = False
                    if memseg != None :
                        memseg.name = line.split(":")[0].strip()
                elif line.startswith("    ")and memseg != None:
                    if "base_addr:" in line:
                        memseg.start = int(line.split("base_addr: ")[1].strip(),16)
                    elif "size:" in line:
                        memseg.size = int(line.split("size: ")[1].strip(),16)
                    elif "permissions:" in line:
                        memseg.isreadonly = not ("w" in line.split("permissions: ")[1].strip())
                    elif "ivt_offset:" in line:
                        self.vecbase = memseg.start + int(line.split("ivt_offset: ")[1].strip(),16)
                        
                else:
                    pass 

        if memseg != None:
            self.mems.append(memseg)
