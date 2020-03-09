import sys
from program import program

reg = 0
mem = [0 for _ in range(10)]
p = 0
pc = 0
buf = ""

print(program)

while pc < len(program):
    op = program[pc]

    if op == "+":
        reg += 1
    elif op == "-":
        reg -= 1
    elif op == "*":
        reg *= mem[p]
    elif op == "%":
        reg = mem[p] % reg
    elif op == "l":
        reg = mem[p]
    elif op == "s":
        mem[p] = reg
    elif op == ">":
        p = (p + 1) % 10
    elif op == "<":
        p = (p - 1) % 10
    elif op == ",":
        a = sys.stdin.buffer.read(1)
        if not a:
            reg = 0
        else:
            reg += ord(a)
    elif op == "p":
        buf += str(reg)
    elif op == "[":
        if reg == 0:
            cnt = 1
            while cnt != 0:
                pc += 1
                if program[pc] == "[":
                    cnt += 1
                if program[pc] == "]":
                    cnt -= 1
    elif op == "]":
        if reg != 0:
            cnt = 1
            while cnt != 0:
                pc -= 1
                if program[pc] == "[":
                    cnt -= 1
                if program[pc] == "]":
                    cnt += 1
    elif op == "M":
        print(mem)

    pc += 1

print(buf)
