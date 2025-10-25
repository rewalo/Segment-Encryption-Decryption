#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>
#include <type_traits>
#include <vector>

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

// Eventually we might want to swap in a stronger crypto algorithm here.
// For now, XOR is fine to demonstrate the concept, and extremely fast.
#define USE_XOR_ENCRYPTION 1        // 0 = stash is left in plaintext. Useful for debugging, but this should never be used in production. (Obviously.)
#define SED_DEBUG_KEEP_DECRYPTED 0  // 1 = EndSED() leaves code decrypted
#define SED_DEBUG_SLEEP 0           // 1 = Sleep() before re-encrypting

#if USE_XOR_ENCRYPTION
// xor_key is constexpr data in .rdata, never mutated. Eventually we might want to generate this per-build, or mutate it at runtime.
static constexpr unsigned char xor_key[] =
"YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn";
static constexpr size_t xor_key_size = sizeof(xor_key) - 1;
#endif

// ------------------------------------------------------------
// Scoped memory protection
// ------------------------------------------------------------
// We temporarily flip page protection (executable -> writable, etc.)
// and make sure it always gets restored when we leave the scope.
class ScopedProtect final {
public:
    ScopedProtect(void* addr, SIZE_T sizeBytes, DWORD newProt) noexcept
        : _addr(addr), _size(sizeBytes), _restoreNeeded(FALSE), _oldProt(0) {
        if (!_addr || _size == 0) return;

        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(_addr, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.Protect == newProt) {
            _oldProt = mbi.Protect;
            _restoreNeeded = TRUE;
            return;
        }

        if (::VirtualProtect(_addr, _size, newProt, &_oldProt))
            _restoreNeeded = TRUE;
    }

    ~ScopedProtect() {
        if (_restoreNeeded && _addr && _size && _oldProt) {
            DWORD tmp;
            ::VirtualProtect(_addr, _size, _oldProt, &tmp);
        }
    }

    ScopedProtect(const ScopedProtect&) = delete;
    ScopedProtect& operator=(const ScopedProtect&) = delete;

private:
    void* _addr;
    SIZE_T _size;
    BOOL _restoreNeeded;
    DWORD _oldProt;
};

// ------------------------------------------------------------
// Tiny RNG
// ------------------------------------------------------------
// Used to generate per-cycle wipe data so memory patterns never repeat. There's better ways to do this, but this is small and fast enough for our purposes.
struct XorShift64 {
    uint64_t state;
    explicit XorShift64(uint64_t s) noexcept
        : state(s ? s : 0xdeadbeefcafebabeULL) {
    }

    uint64_t next() noexcept {
        uint64_t x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }

    unsigned char nextByte() noexcept {
        return static_cast<unsigned char>(next() >> 56);
    }
};

// ------------------------------------------------------------
// Core metadata types
// ------------------------------------------------------------

struct EncryptedFunctionEntry;

struct StashHandle {
    std::atomic<unsigned char*> ptr{ nullptr };  // where the encrypted copy lives
    std::atomic<uint64_t> generation{ 0 };       // bump every time we move it
};

struct RetiredStash {
    unsigned char* ptr;                          // old stash VA
    size_t         size;
    uint64_t       retireEpoch;                  // when we stopped using it
};

struct RetiredTable {
    EncryptedFunctionEntry* ptr;                 // old function table
    size_t                  count;
    uint64_t                retireEpoch;
};

struct PendingRelock {
    EncryptedFunctionEntry* fn;                 // which function needs to be wiped+rotated
    uint64_t epochTagged;                       // when we queued it
};

// ------------------------------------------------------------
// Global state
// ------------------------------------------------------------
// Everything below is effectively "the runtime." It's mostly
// atomics + thread_local so we don't need global locks.

inline std::atomic<uint64_t> g_reclaimEpoch{ 1 };               // global epoch counter
inline std::vector<RetiredStash> g_retiredStashes;              // old stash pages to maybe free
inline std::vector<RetiredTable> g_retiredTables;               // old metadata tables to maybe free
inline std::vector<PendingRelock> g_pendingRelock;              // functions waiting to be relocked
inline std::vector<PendingRelock> g_armedRelock;                // eligible to wipe on this / next GC tick
inline std::atomic<EncryptedFunctionEntry*> g_table{ nullptr }; // current published table
inline std::atomic<size_t> g_count{ 0 };                        // number of entries in that table
inline std::atomic<bool> g_handlerReady{ false };               // VEH only installs once
thread_local std::vector<EncryptedFunctionEntry*> g_tls_stack;  // what this thread is "inside"

// ------------------------------------------------------------
// Per-function info
// ------------------------------------------------------------
struct EncryptedFunctionEntry {
    uintptr_t FunctionAddress;          // address of the function's first byte
    uintptr_t ReturnAddress;            // address of the CALL/JMP EndSED inside it
    int64_t   FunctionSize;             // bytes from start -> EndSED call/jmp
    StashHandle stash;                  // encrypted backup storage
    BOOL      IsJMPReturn;              // whether EndSED was tailcalled (jmp) or normal call
    std::atomic<int> ActiveCalls{ 0 };  // how many threads are currently executing it
    uint64_t  seed{ 0 };                // per-function randomness seed for wipe patterns

    EncryptedFunctionEntry() noexcept: 
        FunctionAddress(0),
        ReturnAddress(0),
        FunctionSize(0),
        stash(),
        IsJMPReturn(FALSE),
        ActiveCalls(0),
        seed(0) {
    }
};

// ------------------------------------------------------------
// Public API
// ------------------------------------------------------------
// Every protected function must end with EndSED(...) instead of return.
// EncryptFunction(fn) sets up protection for that function.
__declspec(dllexport) void* EndSED(void* returnValue);
void EncryptFunction(uintptr_t functionPointer);

// ------------------------------------------------------------
// Light crypto / memory scribble helpers
// ------------------------------------------------------------

#if USE_XOR_ENCRYPTION
// Basic XOR over the stash buffer. This is symmetrical: xor twice to get back plaintext.
inline void xor_crypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= xor_key[i % xor_key_size];
}
#endif

// Build a "wipe" image of the function: first bytes are UD2 (0F 0B = illegal instr),
// rest is random junk. Seed changes every cycle so nothing repeats.
inline void generate_random_wipe(unsigned char* buffer, size_t size, uint64_t& seed) {
    if (!buffer || size == 0) return;

    XorShift64 rng(seed);

    const size_t ud2_len = (size >= 16u) ? 16u : size;
    for (size_t i = 0; i < ud2_len; i += 2) {
        buffer[i] = 0x0F;
        if (i + 1 < ud2_len)
            buffer[i + 1] = 0x0B;
    }

    for (size_t i = ud2_len; i < size; ++i)
        buffer[i] = rng.nextByte();

    seed = rng.next(); // evolve per cycle
}

// Copy into executable memory safely, and flush instruction cache so CPUs see updated bytes.
inline void SecureMemcpyCode(void* dst, const void* src, size_t sizeBytes) {
    if (!dst || !src || sizeBytes == 0) return;
    ScopedProtect prot(dst, sizeBytes, PAGE_EXECUTE_READWRITE);
    std::memcpy(dst, src, sizeBytes);
    ::FlushInstructionCache(::GetCurrentProcess(), dst, sizeBytes);
}

// Overwrite live code bytes with UD2 + random junk.
// After this, trying to execute that function will immediately fault.
inline void WipeLiveCodeSection(LPVOID address, int SIZE_OF_FUNCTION, uint64_t& seed) {
    if (!address || SIZE_OF_FUNCTION <= 0) return;

    const size_t sz = static_cast<size_t>(SIZE_OF_FUNCTION);

    constexpr size_t SMALL_SCRATCH = 512;
    unsigned char smallBuf[SMALL_SCRATCH];

    unsigned char* wipeBuf =
        (sz <= SMALL_SCRATCH)
        ? smallBuf
        : static_cast<unsigned char*>(::HeapAlloc(::GetProcessHeap(), 0, sz));

    if (!wipeBuf) return;

    generate_random_wipe(wipeBuf, sz, seed);
    SecureMemcpyCode(address, wipeBuf, sz);

    if (sz > SMALL_SCRATCH)
        ::HeapFree(::GetProcessHeap(), 0, wipeBuf);
}

// ------------------------------------------------------------
// Reclaim helpers
// ------------------------------------------------------------
// We don't free memory the instant we're "done" with it.
// Instead, we tag it with an epoch and only release it after a grace period.
// This prevents use-after-free in other threads that might still be exiting.
inline void ReclaimRetiredStashes() {
    const uint64_t curEpoch = g_reclaimEpoch.load(std::memory_order_acquire);
    const uint64_t minKeepEpoch = (curEpoch > 2u) ? (curEpoch - 2u) : 0u;

    std::vector<RetiredStash> keep;
    keep.reserve(g_retiredStashes.size());

    for (auto& r : g_retiredStashes) {
        if (!r.ptr || r.size == 0) continue;

        bool stillActiveUser = false;

        auto* tbl = g_table.load(std::memory_order_acquire);
        const size_t cnt = g_count.load(std::memory_order_acquire);

        if (tbl && cnt) {
            for (size_t i = 0; i < cnt; ++i) {
                // If some function is still using this exact stash AND it's active,
                // we definitely can't free that memory yet.
                if (tbl[i].stash.ptr.load(std::memory_order_acquire) == r.ptr &&
                    tbl[i].ActiveCalls.load(std::memory_order_acquire) > 0) {
                    stillActiveUser = true;
                    break;
                }
            }
        }

        if (r.retireEpoch < minKeepEpoch && !stillActiveUser) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(r.ptr, &mbi, sizeof(mbi)) == sizeof(mbi) &&
                mbi.State == MEM_COMMIT) {
                ::VirtualFree(r.ptr, 0, MEM_RELEASE);
            }
        }
        else {
            keep.push_back(r);
        }
    }

    g_retiredStashes.swap(keep);
}

inline void ReclaimRetiredTables() {
    const uint64_t curEpoch = g_reclaimEpoch.load(std::memory_order_acquire);
    const uint64_t minKeepEpoch = (curEpoch > 2u) ? (curEpoch - 2u) : 0u;

    std::vector<RetiredTable> keep;
    keep.reserve(g_retiredTables.size());

    for (auto& t : g_retiredTables) {
        if (!t.ptr || t.count == 0) continue;

        if (t.retireEpoch < minKeepEpoch) {
            ::HeapFree(::GetProcessHeap(), 0, t.ptr);
        }
        else {
            keep.push_back(t);
        }
    }

    g_retiredTables.swap(keep);
}

// ------------------------------------------------------------
// Relock / rotation
// ------------------------------------------------------------
// After the last thread leaves a function, we don't instantly nuke it.
// We push it into a "pending relock" list instead, then later (after a grace
// period) we actually wipe the live code again and move its stash to a new VA.
// That relocation step helps break long-term memory forensics.

inline void do_rotation_now(EncryptedFunctionEntry* e) {
    if (!e) return;

#if SED_DEBUG_SLEEP
    ::Sleep(5000); // helpful when debugging / reversing
#endif

#if !SED_DEBUG_KEEP_DECRYPTED
    // Put illegal opcodes + junk back into the live code region.
    WipeLiveCodeSection(reinterpret_cast<LPVOID>(e->FunctionAddress),
        static_cast<int>(e->FunctionSize),
        e->seed);
#endif

    const size_t sz = static_cast<size_t>(e->FunctionSize);
    if (sz == 0) return;

    unsigned char* oldPtr = e->stash.ptr.load(std::memory_order_acquire);
    if (!oldPtr) return;

    // Allocate a brand new stash VA and copy the encrypted bytes over.
    unsigned char* newPtr = static_cast<unsigned char*>(
        ::VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!newPtr) return;

    std::memcpy(newPtr, oldPtr, sz);

    // Lock it back down as read-only so nobody writes into it.
    DWORD tmp;
    ::VirtualProtect(newPtr, sz, PAGE_READONLY, &tmp);

    // Publish the new stash pointer and bump its generation counter.
    e->stash.ptr.store(newPtr, std::memory_order_release);
    (void)e->stash.generation.fetch_add(1, std::memory_order_acq_rel);

    // The old stash memory goes onto the retired list to be freed later.
    const uint64_t retireEpoch = g_reclaimEpoch.load(std::memory_order_acquire);
    g_retiredStashes.push_back(RetiredStash{ oldPtr, sz, retireEpoch });
}

// This function is our "maintenance tick":
inline void ProcessPendingRelocksAndGC() {
    // bump global epoch
    const uint64_t newEpoch =
        g_reclaimEpoch.fetch_add(1, std::memory_order_acq_rel) + 1ULL;

    const uint64_t minRelockEpoch =
        (newEpoch > 2u) ? (newEpoch - 2u) : 0u;

    // ----------------------------------------
    // Stage A: move fresh idle functions from pending -> armed
    // We do NOT wipe them yet. We just "arm" them.
    // ----------------------------------------
    {
        std::vector<PendingRelock> stillPending;
        stillPending.reserve(g_pendingRelock.size());

        for (auto& pr : g_pendingRelock) {
            if (!pr.fn)
                continue;

            // only care about funcs that are fully idle
            const bool idleNow =
                (pr.fn->ActiveCalls.load(std::memory_order_acquire) == 0);

            if (idleNow) {
                // arm it for future wipe (keep original epochTagged)
                g_armedRelock.push_back(pr);
            }
            else {
                // someone went back in, keep waiting
                stillPending.push_back(pr);
            }
        }

        g_pendingRelock.swap(stillPending);
    }

    // ----------------------------------------
    // Stage B: actually wipe/rotate anything in armedRelock
    // that is old enough and still idle.
    //
    // This cannot run in the same logical "frame" that just
    // executed the function unless we've ticked at least once,
    // which is what avoids the crash.
    // ----------------------------------------
    {
        std::vector<PendingRelock> stillArmed;
        stillArmed.reserve(g_armedRelock.size());

        for (auto& pr : g_armedRelock) {
            if (!pr.fn) continue;

            const bool safeNow =
                (pr.epochTagged < minRelockEpoch) &&
                (pr.fn->ActiveCalls.load(std::memory_order_acquire) == 0);

            if (safeNow) {
                do_rotation_now(pr.fn); // wipes code + rotates stash
            }
            else {
                stillArmed.push_back(pr);
            }
        }

        g_armedRelock.swap(stillArmed);
    }

    // normal cleanup of old memory
    ReclaimRetiredStashes();
    ReclaimRetiredTables();
}

// ------------------------------------------------------------
// VEH (Vectored Exception Handler)
// ------------------------------------------------------------
// The idea: the function is wiped with UD2, so executing it triggers
// an illegal-instruction exception. We catch that here, decrypt the
// bytes back into place, and then continue execution like nothing happened.
inline LONG WINAPI VEHDecryptionHandler(PEXCEPTION_POINTERS ex) {
    if (!ex || !ex->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;

    auto* table = g_table.load(std::memory_order_acquire);
    const size_t count = g_count.load(std::memory_order_acquire);
    if (!table || count == 0)
        return EXCEPTION_CONTINUE_SEARCH;

    const auto faultIP =
        reinterpret_cast<uintptr_t>(ex->ExceptionRecord->ExceptionAddress);

    for (size_t i = 0; i < count; ++i) {
        EncryptedFunctionEntry& e = table[i];

        if (e.FunctionSize <= 0 || e.FunctionSize > 0x10000)
            continue;

        if (faultIP != e.FunctionAddress)
            continue;

        // First thread in restores plaintext from stash.
        const int prev =
            e.ActiveCalls.fetch_add(1, std::memory_order_acq_rel);

        if (prev == 0) {
            const size_t sz = static_cast<size_t>(e.FunctionSize);
            unsigned char* stashPtr =
                e.stash.ptr.load(std::memory_order_acquire);

            if (stashPtr && sz) {
                // Quick sanity check that memory is still valid and hasn't already
                // been freed by GC.
                MEMORY_BASIC_INFORMATION mbi{};
                if (::VirtualQuery(stashPtr, &mbi, sizeof(mbi)) != sizeof(mbi) ||
                    mbi.State != MEM_COMMIT) {

                    // Stash is gone (shouldn't normally happen, but if it does,
                    // back out so we don't crash this thread immediately).
                    e.ActiveCalls.fetch_sub(1, std::memory_order_acq_rel);
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                // Temporarily allow writes to the stash so we can decrypt in place.
                ScopedProtect stashProt(stashPtr, sz, PAGE_READWRITE);

#if USE_XOR_ENCRYPTION
                xor_crypt(stashPtr, sz); // decrypt in-place
#endif

                // Copy plaintext back over the live function bytes.
                SecureMemcpyCode(
                    reinterpret_cast<void*>(e.FunctionAddress),
                    stashPtr,
                    sz);

#if USE_XOR_ENCRYPTION
                xor_crypt(stashPtr, sz); // re-encrypt it before we leave
#endif
            }
        }

        // Track that this thread is "inside" this protected function now.
        g_tls_stack.push_back(&e);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ------------------------------------------------------------
// VEH install
// ------------------------------------------------------------
// We only want to install the vectored exception handler once.
inline void EnsureVEHInstalled() {
    bool expected = false;
    if (g_handlerReady.compare_exchange_strong(
        expected, true, std::memory_order_acq_rel)) {

        ::AddVectoredExceptionHandler(1, &VEHDecryptionHandler);
    }
}

// ------------------------------------------------------------
// Function analysis
// ------------------------------------------------------------
// We walk the function bytes looking for the CALL/JMP to EndSED.
// That gives us the "real" size we need to protect.
inline bool AnalyzeFunctionForEndSED(uintptr_t fn, EncryptedFunctionEntry& out) {
    if (!fn)
        return false;

    unsigned char* p = reinterpret_cast<unsigned char*>(fn);
    int size = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;

    const SIZE_T region_remaining =
        (reinterpret_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize) - p;

    const int maxScan =
        static_cast<int>((region_remaining < 0x10000 ? region_remaining : 0x10000));

    while (size < maxScan) {
        unsigned char op = *p;

        // Rel32 CALL (E8) or JMP (E9)
        if (op == 0xE8 || op == 0xE9) {
            auto rel = *reinterpret_cast<const int32_t*>(p + 1);
            uintptr_t target = reinterpret_cast<uintptr_t>(p + 5) + rel;

            if (target == reinterpret_cast<uintptr_t>(&EndSED)) {
                out.IsJMPReturn = (op == 0xE9);
                out.ReturnAddress = reinterpret_cast<uintptr_t>(p);
                out.FunctionSize = size;
                return true;
            }
        }

        ++p;
        ++size;
    }

    return false;
}

// ------------------------------------------------------------
// EncryptFunction
// ------------------------------------------------------------
// Called once per function you want protected.
// After this, executing that function will fault, decrypt itself on demand,
// run, then get wiped and rotated again later.
inline void EncryptFunction(uintptr_t functionPointer) {
    if (!functionPointer)
        return;

    EnsureVEHInstalled();

    const size_t oldCount =
        g_count.load(std::memory_order_acquire);
    EncryptedFunctionEntry* oldTable =
        g_table.load(std::memory_order_acquire);

    const size_t newCount = oldCount + 1u;

    // Publish a brand new copy of the table (RCU style).
    EncryptedFunctionEntry* newTable =
        static_cast<EncryptedFunctionEntry*>(
            ::HeapAlloc(::GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                newCount * sizeof(EncryptedFunctionEntry)));
    if (!newTable) {
        return;
    }

    if (oldTable && oldCount) {
        std::memcpy(newTable,
            oldTable,
            oldCount * sizeof(EncryptedFunctionEntry));
    }

    EncryptedFunctionEntry& cur = newTable[newCount - 1u];
    cur.FunctionAddress = functionPointer;

    // Figure out how big the function body actually is.
    if (!AnalyzeFunctionForEndSED(functionPointer, cur)) {
        ::HeapFree(::GetProcessHeap(), 0, newTable);
        return;
    }

    // Seed for wipe pattern randomization.
    cur.seed = static_cast<uint64_t>(functionPointer) ^ __rdtsc();

    const size_t sz = static_cast<size_t>(cur.FunctionSize);

    if (sz != 0u) {
        // Allocate stash memory for the encrypted copy.
        unsigned char* stash = static_cast<unsigned char*>(
            ::VirtualAlloc(nullptr,
                sz,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE));
        if (!stash) {
            ::HeapFree(::GetProcessHeap(), 0, newTable);
            return;
        }

        // Copy original function bytes to stash, then encrypt in place.
        std::memcpy(stash,
            reinterpret_cast<void*>(cur.FunctionAddress),
            sz);

#if USE_XOR_ENCRYPTION
        xor_crypt(stash, sz); // stash now holds ciphertext
#endif

        // Stash lives read-only when idle.
        DWORD oldProt;
        ::VirtualProtect(stash,
            sz,
            PAGE_READONLY,
            &oldProt);

        cur.stash.ptr.store(stash, std::memory_order_release);
        cur.stash.generation.store(0, std::memory_order_release);

        // Now wipe the live code with UD2/junk so first execution will fault.
        WipeLiveCodeSection(reinterpret_cast<LPVOID>(cur.FunctionAddress),
            static_cast<int>(cur.FunctionSize),
            cur.seed);
    }
    else {
        // Extremely tiny leaf bodies can technically hit size==0. We still publish them.
        cur.stash.ptr.store(nullptr, std::memory_order_release);
        cur.stash.generation.store(0, std::memory_order_release);
    }

    // Publish the new table atomically.
    g_table.store(newTable, std::memory_order_release);
    g_count.store(newCount, std::memory_order_release);

    // The previous table (if any) becomes "retired" and will be freed after a grace period.
    if (oldTable && oldCount) {
        const uint64_t retireEpoch =
            g_reclaimEpoch.load(std::memory_order_acquire);
        g_retiredTables.push_back(
            RetiredTable{ oldTable, oldCount, retireEpoch });
    }

    // Run maintenance: bump epoch, maybe relock old functions, maybe free old memory.
    ProcessPendingRelocksAndGC();
}

// ------------------------------------------------------------
// EndSED
// ------------------------------------------------------------
// Every SED-protected function must return through here, not `return <value>`.
// We pop this thread's active function, drop ActiveCalls, and maybe schedule
// a relock for that function.
#pragma optimize("", off)
inline void* EndSED(void* returnValue) {
    if (!g_tls_stack.empty()) {
        EncryptedFunctionEntry* e = g_tls_stack.back();
        g_tls_stack.pop_back();

        if (e) {
            const int remaining =
                e->ActiveCalls.fetch_sub(1, std::memory_order_acq_rel) - 1;

            if (remaining == 0) {
                // last thread just left this function
                // we do NOT wipe here. we just mark it "pending"
                const uint64_t nowEpoch =
                    g_reclaimEpoch.load(std::memory_order_acquire);

                g_pendingRelock.push_back(
                    PendingRelock{ e, nowEpoch });

                // tiny nudge so epochs still advance under light usage
                ProcessPendingRelocksAndGC();
            }
        }
    }

    return returnValue;
}
#pragma optimize("", on)
