# Knock knock (crypto, 172p, 86 solved)

## Description

```
Desynchronized with the current configuration of our knockd server, we are unable to connect to it. Fortunately, we've managed to record some of the server's network traffic, hoping it might help up somehow...

Can you take a look?

N.B. The flag is a string of the form "VolgaCTF{a,b}", where a and b are the current ports from '[openSSH]' configuration block
```

## Task analysis

### Code

In the task we get [source code](task.py) and [network capture](knockd.pcap).
The code is rather simple:

```python
def main():
    rng = mersenne_rng(???)
    for i in range(625):
        number = rng.get_random_number()
        port1 = (number & (2 ** 32 - 2 ** 16)) >> 16
        port2 = number & (2 ** 16 - 1)

        fd = open('/etc/knockd.conf', 'w')
        fd.write('[options]\n')
        fd.write('    UseSyslog\n')
        fd.write('    interface = enp0s3\n')
        fd.write('[openSSH]\n')
        fd.write('    sequence = {0}, {1}\n'.format(port1, port2))
        fd.write('    seq_timeout = 5\n')
        fd.write('    command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT\n')
        fd.write('    tcpflags = syn\n')
        fd.write('[closeSSH]\n')
        fd.write('    sequence = {1}, {0}\n'.format(port1, port2))
        fd.write('    seq_timeout = 5\n')
        fd.write('    command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT\n')
        fd.write('    tcpflags = syn\n')
        fd.close()
        os.system('systemctl restart knockd')
        assert 'Active: active (running)' in os.popen('systemctl status knockd').read()

        time.sleep(5)
```

Where `mersenne_rng` is a standard MT implementation.
It seems that 625 times a port knocking configuration is applied on the server, each time with random port numbers from 32 bit MT output (one port is upper 16 bits, second port lower 16 bits).
Once valid ports are knocked port 2222 gets opened.
Conveniently we need exactly 624 MT outputs to recover the RNG state and predict next values.

### Pcap

In the network capture we can see requests for different ports and some of them are followed by connection to 2222.
There are however also "wrong" attempts where 2 ports are knocked but no 2222 connection is done, which means we need to filter out those.

## Solution

### Filter ports

First step is to get back the knocked ports.
We do this by filtering by IP and SYN packets:

```python
    import pyshark
    results = []
    pcap = pyshark.FileCapture("knockd.pcap")
    for pkt in pcap:
        if str(pkt.ip.addr).endswith('105') and int(pkt.tcp.flags_syn) == 1:
            results.append(pkt.tcp.dstport)
    pcap.close()
    ports = []
```

Now we need to filter out the invalid knocks not followed by 2222:

```python
    ports = []
    i = 0
    while i < len(results) - 2:
        p1 = int(results[i])
        p2 = int(results[i + 1])
        p3 = int(results[i + 2])
        if p1 != 2222 and p2 != 2222 and p3 == 2222:
            ports.append([p1, p2])
            i += 3
        else:
            i += 1
```

We check triplets to match `p1,p2,2222` where p1 and p2 can't be 2222.
We can confirm that we get back exactly 624 port pairs.

### Recover RNG state

First we need to turn pair of ports into 32 bit RNG result:

```python
def invert_port_to_int(port1, port2):
    return ((port1 << 16) + port2) & (2 ** 33 - 1)
```

Once we do that we can just use any MT state recovery script (like https://github.com/eboda/mersenne-twister-recover/blob/master/MTRecover.py ) and run:

```python
def get_flag(ports):
    ints = [invert_port_to_int(p1, p2) for (p1, p2) in ports]
    mtb = MT19937Recover()
    r = mtb.go(ints, forward=True)
    number = r.getrandbits(32)
    port1 = (number & (2 ** 32 - 2 ** 16)) >> 16
    port2 = number & (2 ** 16 - 1)
    return "VolgaCTF{%d,%d}" % (port1, port2)
```

To get `VolgaCTF{15094,7850}`
