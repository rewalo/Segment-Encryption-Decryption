# Segment-Encryption-Decryption (SED)

**Segment-Encryption-Decryption (SED)** is a runtime code-protection system that encrypts functions in memory, decrypts them only during execution, and immediately re-encrypts them afterward.  
This repository is a **complete architectural rewrite** of [**C5Hackr’s original Segment-Encryption (SED)**](https://github.com/C5Hackr/Segment-Encryption).

All credit for the original concept and proof-of-concept implementation goes to [**C5Hackr**](https://github.com/C5Hackr).  
This version re-imagines the system with modern C++ design, thread safety, and lock-free data structures.

**If you find this project useful, please star the repository to support further development!**

---

## What Is SED?

SED protects sensitive code by dynamically encrypting and decrypting functions in memory at runtime. This project enhances the original with:
- **Modern C++ architecture** - replaces global C-style data with typed structures, atomics, and thread-local storage.  
- **Full thread safety** - uses atomic reference counting and TLS call stacks to handle concurrent execution safely.  
- **Lock-free operation** - immutable tables eliminate race conditions and remove the need for global synchronization.  
- **Optimized runtime** - decryption-execution-re-encryption cycles complete in microseconds.  
- **Configurable debugging** - compile-time macros (`SED_DEBUG_KEEP_DECRYPTED`, `SED_DEBUG_SLEEP`) enable inspection without modifying code flow.  
- **Safe memory handling** - uses immutable table publication to prevent use-after-free and concurrent modification issues.

---

## New Dual-Mode Architecture

The latest version introduces **two selectable runtime modes** for flexibility and scalability:

```
#define SED_MODE_VEH         1
#define SED_MODE_TRAMPOLINE  2

#ifndef SED_MODE
    #define SED_MODE SED_MODE_VEH
#endif
```

### **1. SED_MODE_VEH (Default)**
- Original VEH-based approach.
- Replaces protected function code with illegal opcodes (`0x1F`/`0xFE`).
- On execution, triggers `EXCEPTION_ILLEGAL_INSTRUCTION` handled by `VEHDecryptionHandler`.
- Automatically decrypts, executes, and re-encrypts.
- **Advantages:**
  - Seamless, direct calls work as-is.
  - Near 1 µs total cycle time.
- **Limitations:**
  - VEH dispatch is serialized by Windows, limiting multi-thread scalability.

### **2. SED_MODE_TRAMPOLINE**
- New, fully concurrent “JIT-style” mode.
- Does **not** rely on VEH, avoids global handler contention.
- `CallFunction()` performs atomic activation + decryption before running.
- Each thread can independently execute decrypted functions.
- Functions are automatically re-encrypted when the last thread exits.
- **Advantages:**
  - Fully parallel-safe.
  - Avoids VEH bottleneck.
  - ~4 µs runtime performance.
- **Note:** Functions MUST be called via `CallFunction()` in this mode.

---

## How It Works

1. **Initialization**:
   - `EncryptFunction()` encrypts a function’s bytes with XOR, replaces the code with illegal opcodes (`0x1F`/`0xFE`), and sets up a Vectored Exception Handler (VEH) if using VEH mode.
2. **Execution**:
   - In **VEH mode**: `EXCEPTION_ILLEGAL_INSTRUCTION` triggers the VEH handler, which decrypts the function for execution.
   - In **TRAMPOLINE mode**: `CallFunction()` explicitly decrypts and activates the function for each thread.
3. **Post-Execution**:
   - `EndSED()` tracks exiting threads via an atomic counter and re-encrypts the function when the last thread exits.

**Performance:** ~1 µs per SED cycle.  
**Thread Safety:** Atomic operations + thread-local storage ensure safe concurrent use.

---

## Screenshots

**Before Encryption:**

![Before](https://raw.githubusercontent.com/rewalo/Segment-Encryption-Decryption/main/Images/Before.png)

**During Execution (Decrypted):**

![After](https://raw.githubusercontent.com/rewalo/Segment-Encryption-Decryption/main/Images/After.png)

**Sample Output:**

![Output](https://raw.githubusercontent.com/rewalo/Segment-Encryption-Decryption/main/Images/Output.png)

---

## Debug and Development

Since this version re-encrypts functions in roughly 0.5 µs, viewing the decrypted code without an intentional delay is virtually impossible.
To assist with debugging, two optional macros have been added at the top of `SED.h` that control re-encryption behavior:

```cpp
#define SED_DEBUG_KEEP_DECRYPTED 0
#define SED_DEBUG_SLEEP 1
```

| Macro | Description |
|--------|-------------|
| `SED_DEBUG_KEEP_DECRYPTED` | When set to `1`, keeps code decrypted after `EndSED()` (use for inspection). |
| `SED_DEBUG_SLEEP` | When set to `1`, pauses for 5 seconds before re-encryption to allow debugger attachment. |

This makes it possible to pause execution and examine the decrypted code before it is wiped again.

---

## Key Improvements Over Original

This version significantly enhances the original SED project with the following upgrades:

1. **Thread Safety**:
   - Uses an atomic `ActiveCalls` counter to manage concurrent execution safely.
   - Implements thread-local storage (`g_tls_stack`) to track per-thread function state.
   - Ensures race-free global table updates with RCU-style persistence.

2. **Optimized Performance**:
   - Reduces unnecessary `VirtualProtect` and `FlushInstructionCache` calls.
   - Triggers re-encryption only when needed, achieving ~1 µs per decrypt-execute-re-encrypt cycle.

3. **Dual-Mode Runtime (NEW)**:
   - Adds `SED_MODE_TRAMPOLINE` for multi-core scalability.
   - Maintains identical API and behavior as the VEH version.

4. **Redesigned VEH Handler**:
   - Performs a single decryption per function activation.
   - Moves re-encryption to `EndSED()` for race-free execution.

5. **Enhanced Debugging**:
   - Adds configurable macros (`SED_DEBUG_KEEP_DECRYPTED`, `SED_DEBUG_SLEEP`) for inspection.
   - Includes clear lifecycle comments in the source for better understanding.

6. **Improved Testing**:
   - Introduces stress tests (`testFast`, `run_concurrent_same`, etc.) in `SED.cpp`.
   - Provides benchmarks for latency and correctness validation.

7. **Better Code Clarity**:
   - Documents key functions (`EncryptFunction`, `VEHDecryptionHandler`, `EndSED`) in detail.
   - Uses consistent formatting and inline documentation.

---

### Comparison with Original

| Feature | Original | New |
|----------|-----------|------|
| Thread-safe | No | Yes (atomic + TLS) |
| Race-free VEH | No | Yes |
| Debugging support | None | Full (toggles + delay) |
| Memory safety | Partial | Safe, persistent tables |
| Performance | High overhead | ~1 µs per call |
| Clarity | Minimal | Fully documented |
| Multi-thread Scaling | Poor | Full (TRAMPOLINE mode) |
| API Functionality | Same | Same |

---

## Getting Started

1. Include `SED.h` in your project.
2. Call `EncryptFunction()` on target functions (e.g., from `main()`).
3. Ensure each encrypted function ends with `EndSED()`.
4. Build with a C++20 or newer compiler supporting `std::atomic` and `thread_local`.
5. To test both modes:
   - Default (VEH): build as-is.  
   - Trampoline mode: add `-DSED_MODE=SED_MODE_TRAMPOLINE`.
6. Run multithreaded tests in `SED.cpp` to validate behavior.

---

## Known Bugs

**Trampoline Race Condition Issue**  
Under heavy multithreaded churn tests (`run_break_reencrypt_churn`), there is a persistent **race condition** that causes intermittent crashes or invalid state if a thread exits exactly as another re-encrypts the same region (2+ threads).  
This will be addressed in the next update (possibly a refined atomic handoff for re-encryption synchronization?)

---

## Disclaimer

This project is for **educational and research purposes only**, building on the original concept and design by C5Hackr.  
Use responsibly and in compliance with all applicable laws.  
The author assumes no liability for misuse.

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**  
See the [LICENSE](LICENSE) file for details.