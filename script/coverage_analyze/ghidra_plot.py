#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.block import CodeBlockModel
from ghidra.util.task import TaskMonitor
from java.awt import Color
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os


collsion = 0
tained_bbls = 0
class addr_range:
    def __init__(self):
        pass

def hash_32(number):
    return number
     
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


bbl_id_mapping = {}
coverages = []
def generate_mapping():
    global collsion
    bbm = SimpleBlockModel(currentProgram)
    blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
    block = blocks.next()
    i = 1
    while block:
        addr = int(str(block.minAddress),16)
        bbl_id = hash_32(addr) % (1 << 16)
        range = addr_range()
        range.start = block.minAddress
        range.end = block.maxAddress
        if bbl_id in bbl_id_mapping:
            #print hex(addr),bbl_id_mapping[bbl_id].start
            collsion += 1
        bbl_id_mapping[bbl_id] = range
        block = blocks.next()

with open("coverage.bin","rb") as f:
    buf = f.read()
    for i in range(len(buf)):
        if ord(buf[i]) != 0xff:
            coverages.append(i)

print os.getcwd()
COLOR_CALL = Color(255, 100, 100)
service = state.getTool().getService(ColorizingService)
if service is None:
     print "Can't find ColorizingService service"
generate_mapping()


for coverage in coverages:
    try:
        b = AddressSet(bbl_id_mapping[coverage].start,bbl_id_mapping[coverage].end)
        service.setBackgroundColor(b, COLOR_CALL)
        tained_bbls += 1
        #print bbl_id_mapping[coverage].start,bbl_id_mapping[coverage].end
    except:
	#pass
        print "error",hex(coverage)

print "collsion",collsion
print "len(bbl_id_mapping)",len(bbl_id_mapping)
print "tained_bbls",tained_bbls







