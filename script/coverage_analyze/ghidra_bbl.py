#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

import sys
from ghidra.program.model.block import SimpleBlockIterator
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import TaskMonitor

bbm = SimpleBlockModel(currentProgram)
blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
block = blocks.next()
bbs = set()

while block:
    bbs.add(block.getFirstStartAddress())
    block = blocks.next()

fout = "./cov-bbs.yaml"
with open(fout, "w") as f:
	for item in bbs:
		f.write(str(item))
		f.write('\n')
		print(item)

print("Output file: {fout}")
print(len(bbs))
