# Flag Checker Revenge - BambooFox CTF 2021 (reverse, 101p)

## Introduction
Flag Checker Revenge is a reverse task.

An x64 ELF binary is given.

## Reverse engineering
The binary reads a password on the standard input. It then checks the size of
the input is `0x2b` bytes.

The binary then calls a serie of 500 functions that all do different checks on
some parts of the flag.

This can be solved with `angr`.

**Flag**: `flag{4ll_7h3_w4y_70_7h3_d33p357_v4l1d4710n}`

## Appendices
### pwn.py
```python
import angr

BASE  = 0x00400000
START = BASE + 0x00009a95
GOOD  = BASE + 0x00009ab7
BAD   = BASE + 0x00009ac5

project = angr.Project("./task")
state   = project.factory.blank_state(addr=START)
state.regs.rbp = state.regs.rsp
state.regs.rsp = state.regs.rbp - 0x50

# Specify the flag
flag = state.solver.BVS("password", 0x2B * 8)
state.memory.store(state.regs.rbp - 0x50, flag)

for i in range(0x2B):
	char = (flag >> (8 * i)) & 0xFF
	state.solver.add(0x20 <= char)
	state.solver.add(char < 0x80)

simulation = project.factory.simgr(state)
simulation.explore(find=GOOD, avoid=BAD)

if simulation.found:
	solution = simulation.found[0].solver.eval(flag)
	print(hex(solution)[2:])
```
