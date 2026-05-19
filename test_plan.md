1. **Explore Codebase and Identify Target**
   - The task is to evolve CleveresTricky into a memory-safe force by migrating C++ components to safe Rust, implementing advanced spoofing, and ensuring zero Zygote crashes.
   - I identified missing `Hardware-Backed Simulation` and `APEX Version Spoofing` mechanisms that can be implemented in Rust and called via the C++ binder interceptor.

2. **Implement Next-Gen Spoofing in Rust**
   - Wrote `rust/cbor-cose/src/apex.rs` to cache and provide spoofed APEX versions.
   - Wrote `rust/cbor-cose/src/hardware_sim.rs` to generate a TEE simulation exploit using ECDSA keys and CBOR.
   - Exported FFI endpoints `rust_apex_spoof_get` and `rust_generate_hardware_simulation_exploit` in `rust/cbor-cose/src/ffi.rs`.
   - Updated C++ header `cleverestricky_cbor_cose.h` to declare the FFI.

3. **Integrate into C++ Layer**
   - Modified `module/src/main/cpp/binder_interceptor.cpp` to call `rust_generate_hardware_simulation_exploit` during initialization, demonstrating TEE simulation payload generation.

4. **Verify Compilation**
   - Run `cargo check` and `cargo build` in `rust/cbor-cose` to ensure the Rust part compiles.
   - Complete pre commit steps to ensure proper testing, verification, review, and reflection are done.

5. **Submit PR**
   - Create PR titled `🔥 God-Mode Evolution: Advanced TEE Simulation & APEX Spoofing (Rust)`
