# Segment-Encryption-Decryption (SED)

**Segment-Encryption-Decryption (SED)** is a runtime code-protection system that encrypts functions in memory, decrypts them only during execution, and immediately re-encrypts them afterward.  
This is a complete modern rearchitecture of [**C5Hackr’s original Segment-Encryption (SED)**](https://github.com/C5Hackr/Segment-Encryption).

All credit for the original concept and proof-of-concept implementation goes to [**C5Hackr**](https://github.com/C5Hackr).  

**If you find this project useful, please star the repository to support further development!**

---

## What Is SED?

SED protects code by dynamically encrypting and decrypting functions in memory at runtime.  
Core features include:

- **Modern C++ design** - strong typing, atomics, and thread-local call stacks.  
- **Full thread safety** - no data races under concurrent execution.  
- **Lock-free global state** - immutable table publication (RCU-style).  
- **Fast runtime** - decrypt–execute–relock cycles complete in microseconds.  
- **Stealth wipe** - functions are cleared with randomized `UD2` sleds + junk bytes instead of static illegal opcodes.  
- **Per-cycle re-randomization** - every wipe differs (no stable memory signature).  
- **Stash relocation** - the encrypted backup moves to a new memory region after each re-lock cycle.  
- **Epoch-based GC** - old stash pages and old function tables are safely reclaimed after a grace period; zero leaks, zero UAFs.  
- **Hardened stash memory** - isolated via `VirtualAlloc`, kept `PAGE_READONLY` or `PAGE_NOACCESS` at rest.  
- **Debug toggles** - macros for inspection pauses and persistent decryption when needed.

---

## How It Works

1. **Initialization**
   - `EncryptFunction()` scans a function, copies its bytes to a per-function encrypted stash (private `VirtualAlloc` region), and overwrites the live code with a randomized `UD2` + junk pattern.  
   - A global **Vectored Exception Handler (VEH)** is installed to handle decryption on demand.

2. **Execution**
   - Executing a wiped function triggers `EXCEPTION_ILLEGAL_INSTRUCTION`.  
   - The VEH decrypts the stash, restores the function bytes, and resumes execution.  
   - Only the first thread decrypts; concurrent threads reuse the live code.

3. **Post-Execution**
   - Each function ends with `EndSED()`, which decrements its atomic `ActiveCalls` counter.  
   - When the last thread exits:
     - The code is wiped again with a new random UD2/junk pattern.  
     - The encrypted stash is **cloned to a new VA region**, and the old region is retired under a new epoch.  
     - **Epoch-based reclamation** frees only those retired stashes and obsolete function tables that are at least one full generation older, ensuring no UAFs while eliminating leaks.

**Performance:** ~1-2 µs per full decrypt/re-encrypt cycle.  
**Thread Safety:** Fully atomic design; no locks or races even under 8+ threads.  
**Memory Safety:** No leaks, no UAFs - epoch-based GC guarantees one-grace-period safety.

---

## Screenshots

**Before Encryption:**  
![Before](https://raw.githubusercontent.com/rewalo/Segment-Encryption-Decryption/main/Images/Before.png)

**During Execution (Decrypted):**  
![After](https://raw.githubusercontent.com/rewalo/Segment-Encryption-Decryption/main/Images/After.png)

**Sample Output:**  
![Output](https://raw.githubusercontent.com/rewalo/Segment-Encryption-Decryption/main/Images/Output.png)

---

## Debug & Inspection

Because functions are re-encrypted almost instantly, inspection requires toggles defined in `SED.h`:

```cpp
#define SED_DEBUG_KEEP_DECRYPTED 0
#define SED_DEBUG_SLEEP 1
```

| Macro | Description |
|--------|-------------|
| `SED_DEBUG_KEEP_DECRYPTED` | Keeps code decrypted after `EndSED()` for inspection. |
| `SED_DEBUG_SLEEP` | Adds a short pause before re-encryption to attach a debugger. |

---

## Key Architecture

### 1. Hardened Memory Layout
- Each function owns its own **encrypted stash** in a `VirtualAlloc` region.  
- Stash is `PAGE_READONLY` at rest; decrypted only inside the VEH window.  
- Live code pages are overwritten with random UD2 sleds after use.

### 2. Per-Cycle Stash Relocation
- After each full execution cycle, the encrypted stash is cloned to a new address.  
- The old stash is moved to a retired list with its epoch tag and freed safely once it’s older than one grace period.  
- This ensures stealth rotation without leaking or racing memory.

### 3. Stealth & Anti-Forensics
- Re-wipes use evolving random seeds per function.  
- No static wipe pattern; every cycle differs in both UD2 layout and junk sequence.  
- Random noise breaks pattern-based opcode signatures completely.

### 4. Multi-Thread + Lock-Free Safety
- Atomic counters manage active threads.  
- Thread-local call stacks (`g_tls_stack`) track active SED calls.  
- No global locks - uses atomic table publication (RCU style).  
- Stash rotations and epoch GC run fully atomically, safe even under 8+ threads.

### 5. VEH Hardening
- Sanity checks ensure:
  - Function size within bounds (≤64KB)  
  - IP matches expected start (no mid-function jumps)  
- Prevents controlled faults or partial decrypts.

---

## Getting Started

1. Include `SED.h` in your project.  
2. Encrypt target functions from `main()`:

```cpp
EncryptFunction(reinterpret_cast<uintptr_t>(myFunction));
```

3. Each protected function **must** end with:

```cpp
return EndSED(returnValue);
```

4. Build with C++17+ and `std::atomic` support.  
5. Run the examples in `SED.cpp` to test.

---

## Validation Suite

SED ships with full internal tests:
- `run_overhead_test_fast()` - microbenchmarks raw cycle cost.  
- `run_concurrent_same()` / `run_concurrent_mixed()` - thread safety validation.  
- `run_break_reencrypt_churn()` - churn race detection.  
- `run_stash_relocation_tests()` - validates relocation, generation increments, epoch GC, and retired stash safety.  

All tests must complete with no `0xC0000005` access violations, all retired stashes still mapped or safely reclaimed, and process exit code **0 (0x0)** under 8-thread churn.

---

## Comparison with Original

| Feature | Original | This Version |
|----------|-----------|--------------|
| Thread Safety | No | Yes (Atomic + TLS) |
| VEH Hardening | No | Yes (Sanity checks) |
| Stash Relocation | No | Yes (Safe per-cycle relocation) |
| Garbage Collection | No | Yes (Leak-free memory reclamation) |
| Memory Wipe | Static 0x1F | Randomized UD2 + junk |
| Debugging | None | Macros + inspection delay |
| Performance | ~Slow | ~1-2µs per call |
| Memory Safety | Partial | Full |
| Locking | Global locks | Lock-free atomic RCU table |

---

## Disclaimer

This project is for **educational and research purposes only**, based on the original design by C5Hackr.  
Use responsibly and in compliance with all applicable laws.  
The author assumes no liability for misuse.

---

## License

Licensed under **GNU GPL v3.0**  
See [LICENSE](LICENSE) for details.
