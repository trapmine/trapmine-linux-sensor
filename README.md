# Trapmine Linux Sensor

## Overview
Trapmine linux sensor is an ebpf based agent for monitoring security relevant events on Linux systems. The sensor collects information from various sources inside the linux kernel, with particular focus on events which can be used to perform security detection and prevention.
The sensor may be used to build a system for detecting process infections, reverse shells, fileless executions, kernel exploits, many other attack vectors.

## Dependecies
- Kernel >= 4.18
- Kernel compiled with CONFIG_DEBUG_INFO_BTF
- clang >= 13.0.0

## Build and Install
> make
> sudo make install

### Build tests
> make build-test


## License
Trapmine Linux Sensor is licensed under GNU GPL v2.0.
