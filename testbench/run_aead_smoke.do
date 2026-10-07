onerror {quit -code 1 -f}

# Run this file from the testbench directory. Only the three AEAD RTL files
# and self-contained testbench assets are needed; no UVM or SoC files.
if {[file isdirectory work_aead_smoke]} {vdel -lib work_aead_smoke -all}
vlib work_aead_smoke
vmap work_aead_smoke ./work_aead_smoke

foreach source {chacha20_core.v poly1305_core.v aead_chacha20_poly1305.v} {
    vlog -work work_aead_smoke [file join .. rtl $source]
}
vlog -work work_aead_smoke tb_aead_core_gui.v

puts "=== AEAD sample: Ciphertext and MAC follow ==="
vsim work_aead_smoke.tb_aead_core_gui +VECTOR=aead_test_vector.txt
run -all
