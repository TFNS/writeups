import subprocess

REPLACE_ME = "XXXX"

ret = subprocess.run(["make", "clean"])
assert ret.returncode == 0

ret = subprocess.run(["make", "shellcode"])
assert ret.returncode == 0


with open("./sc.bin", "rb") as f:
    shellcode_raw = f.read()

shellcode_str = ""
for x in list(shellcode_raw):
    shellcode_str += f"{hex(x)}, "

with open("template.c", "r") as f:
    template = f.read()

exploit = template.replace(REPLACE_ME, shellcode_str)

with open("solve.c", "w") as f:
    f.write(exploit)


ret = subprocess.run(["make", "pwn"])
assert ret.returncode == 0
