# KDProcDumper

## Overview
KDProcDumper is a tool for kernel-mode process dumping, it is made of a Kernel-mode component and a User-mode component.
The KM component will dump the process memory (only a specific module, provided by the UM component).
The UM component communicates with the KM component in the following way:
- Asks the KM component to get the size of a specific module
- Asks the KM component to dump that module

Finally, the UM component will fix the PE file, adjusting the section headers, optional header and the debug directory

## Features
- Kernel-mode process dumping
- Specific module dumping
- IOCTL communication between UM and KM
- PE file fixes
