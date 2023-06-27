# Pepega packets (misc, 5 solves, 395p)

## Introduction

We get golang source code of some [server](server.go) to work with, and network access to where this is running.

## Task analysis

The code is pretty straightforward:

1. There is a loop which goes over all packets and "bans" the sender for a minute.
2. There is `/flag` endpoint which will return a flag if we can stay "not banned" for 5 seconds.

So the goal is to somehow not get banned for long enough to retrieve the flag.

## Solution

The "unintended", although very popular, way to solve this was to simply flood the server.
The idea was that flooding the server with lots of packets will either: 

1. Make the banning loop backlog long enough to not reach our flag request before 5 seconds expire
2. Overflow the packets buffer so that `GetPacketStream` will skip some packets bettween the executions of `workerFirewall`

Regardless of what exectly happened, this was enough to retrieve the flag: `p4{wow-you-are-very-fast-pepega!}`
