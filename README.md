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
Use the controller to populate the ipv4 table in Pod topology _Switch 1_.

**Important**: install p4runtime-shell with the latest features (The release in PyPI is older) directly from git using
```
pip install git+<P4Runtime-shell Repository>
```

####Running the controller
* Delete the entries in _s1-runtime.json_




* On terminal 1 run:
```
make run
```
* On terminal 2 run:
```
python3 controller.py
```

* On terminal 1 try
```
h1 ping h3
```

Ping should work after 1-2 packets are sent.
## References
* INT P4 headers, receive and send python scripts partially forked from [github.com/leandrocalmeida](https://github.com/leandrocalmeida/P4)
* P4 [p4lang/tutorials](https://github.com/p4lang/tutorials)
* P4 GTP traffic handling [GTPV1-P4](https://github.com/Dscano/GTPV1-P4.git)