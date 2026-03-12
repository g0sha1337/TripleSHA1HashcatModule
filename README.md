# TripleSHA1HashcatModule

Triple SHA1 with Hex Conversion
Custom [Hashcat](https://github.com/hashcat/hashcat) module and kernels for cracking the `sha1($salt.hex(sha1($salt.hex(sha1($pass)))))` algorithm.

**Hash Mode:** `4530`

## Features

This project was developed as a joint course project and includes:

- **Hashcat v7+ Support**: Fully compatible with the latest Hashcat architecture.
- **Pure Kernels (`-pure.cl`)**: Supports Dictionary (`-a 0`), Combinator (`-a 1`), and Mask (`-a 3`) attacks. Handles dynamic password lengths up to 256 bytes.
- **Optimized Kernels (`-optimized.cl`)**

## Installation / Build

To integrate this module into Hashcat, copy the files into your Hashcat source tree and recompile:

1. Copy the C module:
   `module_04530.c` -> `src/modules/`
2. Copy the OpenCL kernels:
   `m04530_a0-pure.cl` -> `OpenCL/`
   `m04530_a1-pure.cl` -> `OpenCL/`
   `m04530_a3-pure.cl` -> `OpenCL/`
   `m04530_a3-optimized.cl` -> `OpenCL/`
3. Recompile Hashcat:
   ```bash
   make clean
   make
   ```
