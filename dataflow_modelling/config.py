



class MemSeg:
    def __init__(self):
        self.ismmio = False
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
    def from_fuzzware_config_file(self,config_file):
        with open(config_file,"r") as f:
            while True:
                line = f.readline()
                if line == "":
                    break
                if "mmio:" in line:
                    base_addr_str = f.readline()
                    permission_str = f.readline()
                    size_str = f.readline()
                    base_addr = int(base_addr_str.split("base_addr: ")[1].strip(),16)
                    permission = permission_str.split("permissions: ")[1].strip()
                    size = int(size_str.split("size: ")[1].strip(),16)
                    memseg = MemSeg()
                    memseg.ismmio = True
                    memseg.start = base_addr
                    memseg.size = size
                    if "w" in permission:
                        memseg.isreadonly = False
                    else:
                        memseg.isreadonly = True
                    self.mems.append(memseg)
                elif "ram:" in line:
                    base_addr_str = f.readline()
                    permission_str = f.readline()
                    size_str = f.readline()
                    base_addr = int(base_addr_str.split("base_addr: ")[1].strip(),16)
                    permission = permission_str.split("permissions: ")[1].strip()
                    size = int(size_str.split("size: ")[1].strip(),16)
                    memseg = MemSeg()
                    memseg.ismmio = False
                    memseg.start = base_addr
                    memseg.size = size
                    if "w" in permission:
                        memseg.isreadonly = False
                    else:
                        memseg.isreadonly = True
                    self.mems.append(memseg)
                elif "text:" in line:
                    base_addr_str = f.readline()
                    file_str = f.readline()
                    ivt_offset_str = f.readline()
                    permission_str = f.readline()
                    size_str = f.readline()
                    base_addr = int(base_addr_str.split("base_addr: ")[1].strip(),16)
                    file = file_str.split("file: ")[1].strip()
                    ivt_offset = int(ivt_offset_str.split("ivt_offset: ")[1].strip(),16)
                    permission = permission_str.split("permissions: ")[1].strip()
                    size = int(size_str.split("size: ")[1].strip(),16)
                    memseg = MemSeg()
                    memseg.ismmio = False
                    memseg.start = base_addr
                    memseg.size = size
                    if "w" in permission:
                        memseg.isreadonly = False
                    else:
                        memseg.isreadonly = True
                    self.vecbase = base_addr + ivt_offset
                    self.mems.append(memseg)

