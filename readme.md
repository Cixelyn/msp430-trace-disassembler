quick and dirty msp430 disassembler, specifically geared towards instruction trace output from [msp430-emu-uctf](https://github.com/cemeyer/msp430-emu-uctf)

Written because I wanted something lightweight and self contained.  The other [project I found](https://github.com/SaitoYutaka/MSP430-Disassembler) unfortunantely decodes certain instructions incorrectly. also doesn't convert certain instructions to their easier-to-read emulated form e.g: `mov #0, r3` -> `nop`, which helps when skimming through output.

`./disassembler.py -h` for usage instructions. takes input via binary file or via stdin:

```
$ echo '0e4c 0d40 3d50 0c00' | ./disassembler.py -x -
      0: 0E4C           mov    R12, R14
      1: 0D40           mov    PC, R13
      2: 3D50 0C00      add    #0xc, R13
```
