# Fuzzing mbed-coap with AFL++

This document explains how to use the provided fuzzing setup to test the `sn_coap_parser` function of the mbed-coap library.

## 1. Requirements

*   **AFL++**: This fuzzer is built on AFL++. You must have it installed. You can find the installation instructions on the [official AFL++ GitHub repository](https://github.com/AFLplusplus/AFLplusplus). We recommend using `afl-clang-lto` as the compiler.
*   **Build tools**: A working C compiler (like `clang`) and `make` are required.

## 2. Compilation

To compile the fuzzer harness, navigate to the `fuzz` directory and run `make`:

```bash
cd fuzz
make
```

This will produce an executable file named `parser_fuzzer` in the `fuzz` directory. The binary is instrumented with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) to detect memory errors.

To clean the build artifacts, you can run:
```bash
make clean
```

## 3. Running the Fuzzer

Once the fuzzer is compiled, you can start a fuzzing session with the following command from the `fuzz` directory:

```bash
afl-fuzz -i seeds -o findings -- ./parser_fuzzer
```

### Command-line options:

*   `-i seeds`: Specifies the input directory, which contains the initial test cases (seeds). We've provided a minimal CoAP packet in this directory.
*   `-o findings`: Specifies the output directory where AFL++ will store its findings (crashes, hangs, etc.).
*   `-- ./parser_fuzzer`: The command to execute the target binary.

AFL++ will then start fuzzing the `sn_coap_parser` function. Any crashes or hangs will be saved in the `findings` directory for later analysis.

## 4. Architecture

*   `fuzzer.c`: This is the fuzzing harness. It uses AFL++'s persistent mode for high performance. It reads data from AFL++, initializes the CoAP handle, calls `sn_coap_parser`, and then cleans up.
*   `Makefile`: This file contains the logic to build the `parser_fuzzer` executable, linking it with the mbed-coap source files. It uses `afl-clang-lto` for compilation and enables sanitizers.
*   `seeds/`: This directory contains initial input files to kickstart the fuzzing process.
*   `run.sh`: A simple script to automate the compilation and execution of the fuzzer. 