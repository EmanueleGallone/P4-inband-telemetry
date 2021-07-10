![Generic badge](https://img.shields.io/badge/PythonVersions-3.8-green.svg)

## Introduction

The objective is to implement an In-band Telemetry tool using P4, allowing Prometheus to scrape the data.

We will use the following topology. It is a single
pod of a fat-tree topology and henceforth referred to as pod-topo:
![pod-topo](./pod-topo/pod-topo.png)

## Prerequisite
make sure to have:
* P4-Dev environment (easiest way is to use a [VM](https://drive.google.com/file/d/13SwWBEnApknu84fG9otwbL5NC78tut-d/view))
* scapy installed (see requirements.txt)

## Getting started
Run the following command to start the program
```bash
make run
```
open shells on h1 and h4
```bash
xterm h1 h4
```

run send.py and receive.py

#### Cleaning up Mininet

In the latter two cases above, `make run` may leave a Mininet instance
running in the background. Use the following command to clean up
these instances:

```bash
make stop
```

## Extras
Use the controller to populate the ipv4 table in _Switch 1_.
* Delete the entries in _s1-runtime.json_
* On terminal 1 run:
```
python3 controller
```
* On terminal 2 run:
```
python3 controller
```

* On terminal 1 try
```
h1 ping h3
```

Ping should work after 2-3 packets are sent.
## References
Partially forked from [github.com/leandrocalmeida](https://github.com/leandrocalmeida/P4)
