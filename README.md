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


## How It Works

1. **Initialization**:
   - `EncryptFunction()` encrypts a function’s bytes with XOR, replaces the code with illegal opcodes (`0x1F`/`0xFE`), and sets up a Vectored Exception Handler (VEH).
2. **Execution**:
   - An `EXCEPTION_ILLEGAL_INSTRUCTION` triggers the `VEHDecryptionHandler`, which atomically decrypts the function for execution (only the first thread performs decryption).
3. **Post-Execution**:
   - `EndSED()` tracks exiting threads via an atomic counter and re-encrypts the function when the last thread exits.

**Performance:** ~1 µs per SED cycle.\
**Thread Safety**: Uses `std::atomic` and `thread_local` to handle concurrent access safely.

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
To assist with debugging, two optional macros have been added at the top of SED.h that control re-encryption behavior:

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

3. **Redesigned VEH Handler**:
   - Performs a single decryption per function activation, avoiding redundant memory edits.
   - Moves re-encryption to `EndSED()`, eliminating race conditions.

4. **Enhanced Debugging**:
   - Adds configurable macros (`SED_DEBUG_KEEP_DECRYPTED`, `SED_DEBUG_SLEEP`) for code inspection.
   - Includes clear lifecycle comments in the code for better understanding.

5. **Improved Testing**:
   - Introduces stress tests (`testFast`, `run_concurrent_same`, etc.) in `SED.cpp`.
   - Provides metrics for correctness and latency to validate performance.

6. **Better Code Clarity**:
   - Documents key functions (`EncryptFunction`, `VEHDecryptionHandler`, `EndSED`) thoroughly.
   - Uses section banners and inline comments for improved readability.

### Comparison with Original

| Feature | Original | New |
|----------|-----------|------|
| Thread-safe | No | Yes (atomic + TLS) |
| Race-free VEH | No | Yes |
| Debugging support | None | Full (toggles + delay) |
| Memory safety | Partial | Safe, persistent tables |
| Performance | High overhead | ~1 µs per call |
| Clarity | Minimal | Fully documented |
| API Functionality | Same | Same |

---

## Getting Started

1. Include `SED.h` in your project.
2. Call `EncryptFunction()` on target functions (e.g., from `main()`).
3. Ensure each encrypted function ends with `EndSED()`.
4. Build with a C++11+ compiler supporting `std::atomic` and `thread_local`.
5. Run the multithreaded examples in `SED.cpp` to test.

---

## Disclaimer

This project is for **educational and research purposes only**, building on the original concept and design by C5Hackr.  
Use responsibly and in compliance with all applicable laws.  
The author assumes no liability for misuse.

---
## License

This project is licensed under the   **GNU General Public License v3.0 (GPLv3)**  
See the [LICENSE](LICENSE) file for details.