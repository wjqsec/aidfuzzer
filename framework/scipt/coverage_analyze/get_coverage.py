
import os



def read_process_mem(pid,addr,size):
    with open("/proc/{}/mem".format(pid),"rb") as f:
        f.seek(addr)
        return f.read(size)


with open("coverage.bin","wb") as f:
    f.write(read_process_mem(6384,0x000055f25a7aaeb0,1 << 16))