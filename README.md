# Segment-Encryption-Decryption (SED)

**Segment-Encryption-Decryption (SED)** is a runtime code-protection system that encrypts functions in memory, decrypts them only during execution, and immediately re-encrypts them afterward.  
This is a complete modern rearchitecture of [**C5Hackr’s original Segment-Encryption (SED)**](https://github.com/C5Hackr/Segment-Encryption).

All credit for the original concept and proof-of-concept implementation goes to [**C5Hackr**](https://github.com/C5Hackr).  

**If you find this project useful, please star the repository to support further development!**

---

## What Is SED?

SED protects sensitive code by dynamically encrypting and decrypting functions in memory at runtime. This project enhances the original with:

- **Modern C++ design** - replaces global C-style data with typed structures, atomics, and thread-local storage and call stacks.
- **Full thread safety** - no data races under concurrent execution.  
- **Lock-free global state** - immutable table publication (RCU-style).  
- **Fast runtime** - decrypt–execute–relock cycles complete in microseconds.  
- **Stealth wipe** - functions are cleared with randomized `UD2` sleds + junk bytes instead of static illegal opcodes.  
- **Per-cycle re-randomization** - every wipe differs (no stable memory signature).  
- **Stash relocation** - the encrypted backup moves to a new memory region after each re-lock cycle.  
- **Garbage Collection** - old stash pages and old function tables are safely reclaimed after a grace period; zero leaks, zero UAFs.  
- **Hardened stash memory** - isolated via `VirtualAlloc`, kept `PAGE_READONLY` or `PAGE_NOACCESS` at rest.  

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

## Debug and Development

Since this version re-encrypts functions in roughly 0.5 µs, viewing the decrypted code without an intentional delay is virtually impossible.
To assist with debugging, two optional macros have been added at the top of SED.h that control re-encryption behavior:

```cpp
#define SED_DEBUG_KEEP_DECRYPTED 0
#define SED_DEBUG_SLEEP 1
```

| Macro | Description |
|--------|-------------|
| `SED_DEBUG_KEEP_DECRYPTED` | Keeps code decrypted after `EndSED()` for inspection. |
| `SED_DEBUG_SLEEP` | Adds a short pause before re-encryption to attach a debugger. |

---

## Key Improvements Over Original

This version significantly enhances the original SED project with the following upgrades:

### 1. Hardened Memory Layout
- Each protected function owns its own **encrypted stash** in a `VirtualAlloc` region.  
- Stashes are `PAGE_READONLY` at rest and decrypted only during VEH handling.  
- Live code pages are wiped after execution using randomized **UD2 sleds + junk patterns**, ensuring no static opcode signature remains.  
- Every wipe uses a per-function RNG seed, so patterns differ on every cycle.

### 2. Per-Cycle Stash & Table Relocation (Epoch-Based GC)
- After each full execution cycle, both the encrypted stash and its metadata table are cloned to new memory regions.  
- The old versions are retired under a **grace epoch model**, guaranteeing zero use-after-free conditions.  
- **Epoch-based garbage collection** safely frees both retired stash pages *and old tables* once they’re at least one generation old, ensuring fully leak-free operation.

### 3. Multi-Thread & Lock-Free Safety
- Thread safety is ensured through atomic `ActiveCalls` counters and a per-thread call stack (`g_tls_stack`).  
- Global tables are published immutably (RCU-style), allowing readers to proceed without locks.  
- All reclamation (stash and table rotation) runs atomically and safely even under heavy multithreaded load.  

### 4. VEH Hardening & Runtime Sanity Checks
- The Vectored Exception Handler verifies:
  - Function size validity (`0 < size ≤ 64KB`)
  - Instruction pointer alignment with the registered function start  
- Prevents controlled-fault exploits or mid-body decrypts.  
- Decryptions and re-encryptions are strictly bounded to valid function regions.

### 5. Optimized Performance & Debuggability
- Re-encryption occurs only when the final thread exits a protected function.  
- Minimizes redundant `VirtualProtect` and `FlushInstructionCache` calls for speed (~1 µs per full decrypt–execute–relock).  
- Debug macros (`SED_DEBUG_KEEP_DECRYPTED`, `SED_DEBUG_SLEEP`) allow inspection pauses or persistent decryption for analysis.  
- Extensive inline comments and section banners clarify lifecycle behavior and implementation intent.

### 6. Validation & Testing
- `run_concurrent_same()` and `run_concurrent_mixed()` for thread-safety stress tests.  
- `run_stash_relocation_tests()` verifying generation increments and epoch-based reclamation.  
- `run_break_reencrypt_churn()` simulating heavy churn to confirm stable re-encrypt/decrypt cycles.  
- All tests must pass without crashes, leaks, or unmapped access under 8+ concurrent threads.

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

## Disclaimer

This project is for **educational and research purposes only**, based on the original design by C5Hackr.  
Use responsibly and in compliance with all applicable laws.  
The author assumes no liability for misuse.

---

## License

Licensed under **GNU GPL v3.0**  
See [LICENSE](LICENSE) for details.
