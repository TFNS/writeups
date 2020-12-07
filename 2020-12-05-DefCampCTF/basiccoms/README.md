# basic coms (forensics, 50p, 170 solved)

## Description

```
Look for it and you shall find the flag.

Flag format: CTF{sha256}
```

In the task we get a 60MB pcap file (not attached).

## Task analysis

We drop the file into NetworkMiner for initial inspection.
There are some `Parameters` extracted so we look there and we can see:

```
/?important=The%20content%20of%20the%20f%20l%20a%20g%20is%20ca314be22457497e81a08fc3bfdbdcd3e0e443c41b5ce9802517b2161aa5e993%20and%20respects%20the%20format
```

So the message is:

```
The content of the f l a g is ca314be22457497e81a08fc3bfdbdcd3e0e443c41b5ce9802517b2161aa5e993 and respects the format
```

And flag is: `CTF{ca314be22457497e81a08fc3bfdbdcd3e0e443c41b5ce9802517b2161aa5e993}`
