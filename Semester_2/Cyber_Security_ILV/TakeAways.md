# Take Aways from Cyber Security ILV

## Take-aways: Shell
- Many shell restrictions are implemented in user space. Therefore, you can circumvent them via user space tricks (loading another program)

## Take-aways: Virtual memory
- Each process has it‘s own virtual memory
- The virtual memory is segmented in pages
- Each page has a permission map (read/write/execute)
- The loader is responsible to prepare the virtual memory from the meta information of the executable (ELF file)

## Take-aways: Linking and Loading
- The executable is dependent on separate shared objects (like DLL in Windows)
- The loader can be influenced via configuration files and environment variables

## Take-aways: GOT/PLT
- In order to be memory efficient commonly used shared objects (respectivly the memory pages) are shared between processes
- The linker has to create the mapping between the internal function call and the imported function
- At first use, the PLT entry is not resolved and holds

## Take-aways: GOT/PLT (2)
- At first use, the PLT entry is not resolved and holds a reference to a dynamic linker function
- The dynamic linker resolves the symbol to the address in virtual memory and stores it in the PLT

## Take-aways: GOT/PLT (3)
- This enables attackers to manipulate the entries themselves and put their own functions in the PLT at runtime

## Take-aways: Kernel
- The interaction between user space and Kernel is done via system calls (syscalls)
- Each system call has a number
- The interface are the CPU registers for syscall number and arguments; a syscall is triggered by an opcode (interrupt or opcode)

## Take-aways: Fuzzing Basics
- Fuzz Testing is part of software development processes to cover negative testing.
- Negative test case generation can be achieved by random ("dumb") input generation.
- The generated input should contribute to explore code coverage and identify unintended program states (which can lead to program crashes).

## Take-aways: Protocols and "Smarter" Fuzzing
- It can be necessary to create an input that follows a certain protocol (HTTP, gRPC, API, ...) to reach parsing or business logic.
- Generic Fuzzers, protocol specific fuzzing and fuzzing frameworks can be used.
- This generates inputs that have values and payloads, as far as the test program covers it.

## Take-aways: Input Mutation
- Complex protocols and file formats makes it hard to cover all (unlimited) combinations of inputs.
- To change (mutate) an existing "known-good" input could achieve effective testing with little efforts.
- The tester does not need to know the internals of the SUT.

## Take-aways: Feedback and Generation Strategies
- Feedback of a test case is essential for effective testing.
- The feedback can be extracted from e.g.
    - log information
    - logic probes
    - program coverage or
    - program crashes.
- The tester can react on the feedback to simply mark test cases or change input generation strategies.

## Take-aways: AFL
- AFL instruments the program to generate feedback
    - adding instrumentation code and compilation
    - adding instrumentation code with emulation
- AFL implements different mutation strategies to generate inputs
- AFL collects edge/block coverage and stores it
- AFL uses genetic algorithms to evolve inputs
- AFL stores the corpus and helps with minimization

## Take-aways: Cross Platform
- The test cases can executed against the program on the same machine, a remote system or a hardware device via an interface.
- The goal in fuzzing is to optimize execution speed to terminate testing (slow hardware, network latency, parallelization).
- The program/system can be emulated, cross-compiled, instrumented or hooked.