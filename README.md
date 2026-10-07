# ChaCha20-Poly1305 AEAD RTL

A Verilog implementation of the ChaCha20-Poly1305 AEAD core intended for
integration into a RISC-V microcontroller system. This repository contains
only the **AEAD RTL, basic testbenches, and Quartus projects**. It does not
include a CPU, bus, SoC, GUI, or UVM environment.

## Repository layout

```text
rtl/
  aead_chacha20_poly1305.v   AEAD core top level
  chacha20_core.v            ChaCha20 core
  poly1305_core.v            Poly1305 core
testbench/
  tb_aead_core_gui.v         Direct AEAD testbench; prints ciphertext and MAC
  aead_test_vector.txt       Sample AEAD input vector
  run_aead_smoke.do          ModelSim/Questa compile and simulation script
  tb_chacha20_core_kat.v     ChaCha20 known-answer test
  tb_poly1305_arithmetic.v  Poly1305 wide-integer arithmetic reference test
quartus/
  aead_core/                Pure AEAD top-level synthesis project
  aead_fit_harness/         Fitter/timing project with a 32-bit load/read port
```

## Run the AEAD simulation

ModelSim or QuestaSim is required. Open a terminal in the `testbench`
directory and run:

```powershell
cd testbench
vsim -c -do "do run_aead_smoke.do"
```

If `vsim` is not on your `PATH`, use the full path to the installed
`vsim.exe`. The script compiles the three RTL files, runs
`tb_aead_core_gui` with `aead_test_vector.txt`, and prints `Ciphertext:`,
`MAC:`, and the cycle count. The sample vector contains a **150-byte
message** and **35 bytes of AAD**. With the current RTL, its MAC is
`325aa3bec68dd442d9ad28939a3f19df`.

This AEAD testbench **prints the result** but does not automatically compare
the ciphertext and MAC against a reference implementation. The other two
testbenches check ChaCha20 against an RFC 8439 known-answer vector and
Poly1305 against a wide-integer arithmetic model. For a new AEAD vector,
compare the printed output with an independent software implementation
before treating the result as verified.

## Synthesize with Quartus

Target FPGA: **Cyclone II EP2C35F672C6 (DE2 board)**. The projects were
created with **Quartus II 13.0 SP1**.

1. Open `quartus/aead_fit_harness/aead_fit_harness.qpf`.
2. Select **Processing → Start Compilation**.
3. In **Compilation Report → Fitter → Resource Section → Fitter Resource
   Utilization by Entity**, read the `u_aead` row for the **core-only area**.
4. In **TimeQuest Timing Analyzer → Slow Model Fmax Summary**, read the
   post-fit Fmax.

The `quartus/aead_core/aead_core.qpf` project uses the pure AEAD core as its
top level and is useful for **Analysis & Synthesis**. That top level has too
many I/O bits to fit directly on the EP2C35. The `aead_fit_harness` project
exposes a 32-bit load/read port so the Fitter and TimeQuest can run.

Measurements for the current RTL with a **10 ns clock constraint**, `AREA`
optimization, and Fitter seed 2:

| Post-fit metric | Result |
| --- | ---: |
| Slow-model Fmax | **103.14 MHz** |
| Logic elements in `u_aead` only | **5,751 LE** |
| Logic elements in the full project, including the harness | **6,823 LE** |
| Embedded 9-bit multiplier elements | **8** |

The Fmax figure covers **register-to-register paths** with the core inside
the harness. The SDC constrains the clock but does not specify input/output
delays or DE2 pin assignments. It therefore does not establish board-level
I/O timing, and it is not an ASIC PPA result.

## Interface and current limitations

`aead_chacha20_poly1305` accepts a 256-bit key, a 96-bit nonce, AAD in
16-byte blocks, and payload blocks of up to 64 bytes. The `start_keygen`,
`start_aad`, `start_encrypt`/`start_decrypt`, and `start_finalize` inputs are
one-cycle command pulses. Completion is indicated by `keygen_done`,
`aad_done`, `encrypt_done` (for both encrypt and decrypt), or `finalize_done`.
A typical transaction generates the Poly1305 one-time key,
processes AAD, processes payload blocks, and then processes the length
block and finalizes the MAC.

In decrypt mode, the core computes plaintext and a MAC, but it has **no
received-tag input or authentication pass/fail output**. Integration logic
must compare the received tag and release plaintext only after successful
authentication. This repository does not include a bus or processor; those
interfaces belong to a later SoC integration stage.
