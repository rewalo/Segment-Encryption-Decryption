#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <cstdint>
#include <cstdarg>
#include <cstddef>
#include <atomic>
#include <cstring>
#include <type_traits>
#include <vector>

// ------------------------------------------------------------
// Config / encryption settings
// ------------------------------------------------------------
#define USE_XOR_ENCRYPTION 1

// Debug knobs: slow or skip re-lock for inspection
#define SED_DEBUG_KEEP_DECRYPTED 0  // 1 = EndSED() will NOT re-encrypt at exit
#define SED_DEBUG_SLEEP 0           // 1 = Sleep() before re-encrypting

#if USE_XOR_ENCRYPTION
static constexpr unsigned char xor_key[] = "YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn";
static constexpr size_t xor_key_size = sizeof(xor_key) - 1;
#endif

// ------------------------------------------------------------
// Tiny PRNG (used to randomize wipe patterns)
// ------------------------------------------------------------
struct XorShift64 {
    uint64_t state;
    explicit XorShift64(uint64_t s) noexcept
        : state(s ? s : 0xdeadbeefcafebabeULL) {
    }

    inline uint64_t next() noexcept {
        uint64_t x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }

    inline unsigned char nextByte() noexcept {
        return static_cast<unsigned char>(next() >> 56);
    }
};

// ------------------------------------------------------------
// Forward decls for types referenced across the file
// ------------------------------------------------------------
struct EncryptedFunctionEntry; // forward so RetiredTable can hold a pointer

// ------------------------------------------------------------
// Stash indirection + retire list + epoch GC
// + table GC (RCU-ish, reclaimed after grace epoch)
// ------------------------------------------------------------
struct StashHandle {
    std::atomic<unsigned char*> ptr{ nullptr };
    std::atomic<uint64_t>       generation{ 0 };
};

struct RetiredStash {
    unsigned char* ptr;
    size_t         size;
    uint64_t       retireEpoch;
};

struct RetiredTable {
    // old function metadata table we replaced with a new one
    EncryptedFunctionEntry* ptr;
    size_t                  count;       // number of entries in that table
    uint64_t                retireEpoch;
};

// Global epoch for deferred reclamation of stashes AND tables
inline std::atomic<uint64_t> g_reclaimEpoch{ 1 };

// ------------------------------------------------------------
// Per-function metadata
// ------------------------------------------------------------
struct EncryptedFunctionEntry {
    uintptr_t FunctionAddress;          // start of code region
    uintptr_t ReturnAddress;            // CALL/JMP to EndSED inside func
    int64_t   FunctionSize;             // size in bytes
    StashHandle stash;                  // encrypted stash VA + gen
    BOOL      IsJMPReturn;              // legacy
    std::atomic<int> ActiveCalls{ 0 };  // active threads in this function
    uint64_t  seed{ 0 };                // wipe RNG seed (mutates per cycle)

    EncryptedFunctionEntry() noexcept
        : FunctionAddress(0),
        ReturnAddress(0),
        FunctionSize(0),
        stash(),
        IsJMPReturn(FALSE),
        ActiveCalls(0),
        seed(0) {
    }
};

// ------------------------------------------------------------
// Global state
// ------------------------------------------------------------

// Retired stash pages (to VirtualFree after grace epoch)
inline std::vector<RetiredStash> g_retiredStashes;

// Retired function tables (to HeapFree after grace epoch)
inline std::vector<RetiredTable> g_retiredTables;

// Global table of protected functions (append-only publish)
// NOTE: EncryptFunction() allocates a fresh table that copies old entries +
// new entry, then atomically swaps g_table/g_count. The previous table is
// pushed into g_retiredTables with an epoch tag and reclaimed later.
inline std::atomic<EncryptedFunctionEntry*> g_table{ nullptr };
inline std::atomic<size_t> g_count{ 0 };
inline std::atomic<bool> g_handlerReady{ false };

// TLS call stack (tracks current function for this thread)
thread_local std::vector<EncryptedFunctionEntry*> g_tls_stack;

// ------------------------------------------------------------
// Public API
// ------------------------------------------------------------
template <typename Fn, typename... Args>
inline void* CallFunction(Fn fn, Args... args) {
    // NOTE: Assumes target is __cdecl-like: first param is ignored "context".
    // This keeps behavior identical to original.
    return reinterpret_cast<void* (__cdecl*)(void*, Args...)>(fn)(
        nullptr, std::forward<Args>(args)...);
}

__declspec(noinline) void* CallFunction(void* ptr, ...);
__declspec(dllexport) void* EndSED(void* returnValue);
__declspec(noinline) void EncryptFunction(uintptr_t functionPointer);

// ------------------------------------------------------------
// XOR encrypt/decrypt helper
// ------------------------------------------------------------
#if USE_XOR_ENCRYPTION
inline void xor_crypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= xor_key[i % xor_key_size];
}
#endif

// ------------------------------------------------------------
// generate_random_wipe
// UD2 sled + junk, and mutate 'seed' so pattern changes each cycle
// ------------------------------------------------------------
inline void generate_random_wipe(unsigned char* buffer, size_t size, uint64_t& seed) {
    XorShift64 rng(seed);

    // First bytes = UD2 sled (0F 0B). Forces immediate fault when executed.
    const size_t ud2_len = (size >= 16) ? 16 : size;
    for (size_t i = 0; i < ud2_len; i += 2) {
        buffer[i] = 0x0F;
        if (i + 1 < ud2_len)
            buffer[i + 1] = 0x0B;
    }

    // Remainder = random junk (no obvious "all 0x1F" sig)
    for (size_t i = ud2_len; i < size; ++i)
        buffer[i] = rng.nextByte();

    // Evolve the seed so next wipe differs too
    seed = rng.next();
}

// ------------------------------------------------------------
// WipeLiveCodeSection
// Flip RX->RW, write UD2/junk, restore original prot
// ------------------------------------------------------------
__declspec(noinline) inline void WipeLiveCodeSection(
    LPVOID address,
    int SIZE_OF_FUNCTION,
    uint64_t& seed) {

    if (SIZE_OF_FUNCTION <= 0) {
        return;
    }

    DWORD oldProtect;
    ::VirtualProtect(address,
        static_cast<SIZE_T>(SIZE_OF_FUNCTION),
        PAGE_EXECUTE_READWRITE,
        &oldProtect);

    std::vector<unsigned char> wipeBuf(static_cast<size_t>(SIZE_OF_FUNCTION));
    generate_random_wipe(wipeBuf.data(),
        static_cast<size_t>(SIZE_OF_FUNCTION),
        seed);

    std::memcpy(address,
        wipeBuf.data(),
        static_cast<size_t>(SIZE_OF_FUNCTION));

    ::FlushInstructionCache(::GetCurrentProcess(), address, static_cast<SIZE_T>(SIZE_OF_FUNCTION));

    ::VirtualProtect(address,
        static_cast<SIZE_T>(SIZE_OF_FUNCTION),
        oldProtect,
        &oldProtect);
}

// ------------------------------------------------------------
// ReclaimRetiredStashes
// Free stash pages whose retireEpoch is strictly older than (curEpoch - 1).
// We keep the newest epoch's pages around for one grace window so VEH
// can't race reading a just-freed stash.
// ------------------------------------------------------------
__declspec(noinline) inline void ReclaimRetiredStashes() {
    const uint64_t curEpoch = g_reclaimEpoch.load(std::memory_order_acquire);

    // Oldest epoch we're NOT allowed to touch yet
    // Example:
    //   curEpoch = 7
    //   minKeepEpoch = 6
    //   any stash with retireEpoch < 6 is now fair to free
    const uint64_t minKeepEpoch = (curEpoch > 1) ? (curEpoch - 1) : 0;

    std::vector<RetiredStash> keep;
    keep.reserve(g_retiredStashes.size());

    for (auto& r : g_retiredStashes) {
        if (r.retireEpoch < minKeepEpoch) {
            ::VirtualFree(r.ptr, 0, MEM_RELEASE);
        }
        else {
            keep.push_back(r);
        }
    }

    g_retiredStashes.swap(keep);
}

// ------------------------------------------------------------
// ReclaimRetiredTables
// Any table whose retireEpoch is strictly older than (curEpoch - 1) is freed.
// Just like stashes, we always leave at least one epoch of grace in case a
// VEH handler on another core is still iterating an older snapshot.
// ------------------------------------------------------------
__declspec(noinline) inline void ReclaimRetiredTables() {
    const uint64_t curEpoch = g_reclaimEpoch.load(std::memory_order_acquire);
    const uint64_t minKeepEpoch = (curEpoch > 1) ? (curEpoch - 1) : 0;

    std::vector<RetiredTable> keep;
    keep.reserve(g_retiredTables.size());

    for (auto& t : g_retiredTables) {
        if (t.retireEpoch < minKeepEpoch) {
            if (t.ptr) {
                ::HeapFree(::GetProcessHeap(), 0, t.ptr);
            }
        }
        else {
            keep.push_back(t);
        }
    }

    g_retiredTables.swap(keep);
}

// ------------------------------------------------------------
// GlobalReclaim()
// Helper: run both reclaim passes. We centralize this so any code path
// that advances epochs (stash rotation, table publish) can invoke it.
// ------------------------------------------------------------
__declspec(noinline) inline void GlobalReclaim() {
    ReclaimRetiredStashes();
    ReclaimRetiredTables();
}

// ------------------------------------------------------------
// clone_stash_and_rotate
// Called when ActiveCalls hits 0 for this function.
//  - Clone encrypted stash to new VA (RO).
//  - Publish new ptr/gen.
//  - Retire old ptr with an epoch tag.
//  - Bump global epoch AFTER tracking retirement.
//  - GC runs (may free really old retired stashes / tables).
// NOTE: we never leave a just-retired stash/table in "freed" state during the
// same epoch, so VEH can't race a freed resource.
// ------------------------------------------------------------
__declspec(noinline) inline void clone_stash_and_rotate(EncryptedFunctionEntry* e) {
    const size_t sz = static_cast<size_t>(e->FunctionSize);
    if (sz == 0)
        return;

    unsigned char* oldPtr = e->stash.ptr.load(std::memory_order_acquire);
    if (!oldPtr)
        return;

    // New stash VA (RW temp)
    unsigned char* newPtr = static_cast<unsigned char*>(
        ::VirtualAlloc(nullptr,
            sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE));
    if (!newPtr)
        return;

    // Copy ciphertext (stash stays encrypted-at-rest)
    std::memcpy(newPtr, oldPtr, sz);

    // Lock new stash RO
    DWORD dummyProt;
    ::VirtualProtect(newPtr,
        sz,
        PAGE_READONLY,
        &dummyProt);

    // Swap in new stash for future decrypts
    e->stash.ptr.store(newPtr, std::memory_order_release);
    (void)e->stash.generation.fetch_add(1, std::memory_order_acq_rel);

    // Retire old one. We snapshot the current epoch state BEFORE we bump it.
    // This guarantees retiredStash.retireEpoch <= future curEpoch.
    const uint64_t retireEpoch = g_reclaimEpoch.load(std::memory_order_acquire);

    g_retiredStashes.push_back(
        RetiredStash{ oldPtr, sz, retireEpoch });

    // Now advance global epoch (new logical "cycle")
    (void)g_reclaimEpoch.fetch_add(1, std::memory_order_acq_rel);

    // Try to free anything old enough (stashes + tables)
    GlobalReclaim();
}

// ------------------------------------------------------------
// EndSED
// Thread exits protected fn. If last thread out:
//  - wipe live code -> UD2/junk
//  - rotate stash (stash ptr churns, old ptr epoch-retired)
//  - GC runs (may free really old retired stashes / tables)
// ------------------------------------------------------------
#pragma optimize("", off)
__declspec(dllexport) inline void* EndSED(void* returnValue) {
    if (!g_tls_stack.empty()) {
        EncryptedFunctionEntry* e = g_tls_stack.back();
        g_tls_stack.pop_back();

        const int remaining = e->ActiveCalls.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
#if SED_DEBUG_SLEEP
            ::Sleep(5000);
#endif
#if !SED_DEBUG_KEEP_DECRYPTED
            WipeLiveCodeSection(reinterpret_cast<LPVOID>(e->FunctionAddress),
                static_cast<int>(e->FunctionSize),
                e->seed);
#endif
            clone_stash_and_rotate(e);
        }
    }
    return returnValue;
}
#pragma optimize("", on)

// ------------------------------------------------------------
// VEHDecryptionHandler
// Fault on UD2 -> decrypt function into place, bump ActiveCalls, resume.
// Hardening:
//  - size sanity (0 < size <= 64KB)
//  - RIP must equal recorded FunctionAddress (block mid-body jumps)
//  - stash is RO encrypted except brief RW/plaintext window here
//
// NOTE: We intentionally don't hold any global locks here because VEH runs
// under async exception context. We rely on epoch grace to keep g_table and
// stash memory valid long enough even if EncryptFunction() is racing.
// ------------------------------------------------------------
__declspec(noinline) inline LONG WINAPI VEHDecryptionHandler(PEXCEPTION_POINTERS exceptions) {
    const auto code = exceptions->ExceptionRecord->ExceptionCode;
    auto* table = g_table.load(std::memory_order_acquire);
    const size_t count = g_count.load(std::memory_order_acquire);
    if (!table || count == 0) return EXCEPTION_CONTINUE_SEARCH;

    if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        const auto faultIP =
            reinterpret_cast<uintptr_t>(exceptions->ExceptionRecord->ExceptionAddress);

        for (size_t i = 0; i < count; ++i) {
            EncryptedFunctionEntry& e = table[i];

            // sanity check (#5)
            if (e.FunctionSize <= 0 || e.FunctionSize > 0x10000)
                continue;
            if (faultIP != e.FunctionAddress)
                continue;

            const int prev = e.ActiveCalls.fetch_add(1, std::memory_order_acq_rel);

            if (prev == 0) {
                // First thread in: restore function bytes from stash
                DWORD oldCodeProt;
                ::VirtualProtect(reinterpret_cast<LPVOID>(e.FunctionAddress),
                    static_cast<SIZE_T>(e.FunctionSize),
                    PAGE_EXECUTE_READWRITE,
                    &oldCodeProt);

                unsigned char* stashPtr = e.stash.ptr.load(std::memory_order_acquire);
                if (stashPtr) {
                    DWORD oldStashProt;
                    ::VirtualProtect(stashPtr,
                        static_cast<SIZE_T>(e.FunctionSize),
                        PAGE_READWRITE,
                        &oldStashProt);

#if USE_XOR_ENCRYPTION
                    xor_crypt(stashPtr, static_cast<size_t>(e.FunctionSize)); // -> plaintext
#endif
                    std::memcpy(reinterpret_cast<void*>(e.FunctionAddress),
                        stashPtr,
                        static_cast<size_t>(e.FunctionSize));

                    ::FlushInstructionCache(::GetCurrentProcess(),
                        reinterpret_cast<void*>(e.FunctionAddress),
                        static_cast<SIZE_T>(e.FunctionSize));

#if USE_XOR_ENCRYPTION
                    xor_crypt(stashPtr, static_cast<size_t>(e.FunctionSize)); // -> re-encrypt
#endif

                    DWORD tmp;
                    ::VirtualProtect(stashPtr,
                        static_cast<SIZE_T>(e.FunctionSize),
                        PAGE_READONLY,
                        &tmp);
                }

                ::VirtualProtect(reinterpret_cast<LPVOID>(e.FunctionAddress),
                    static_cast<SIZE_T>(e.FunctionSize),
                    oldCodeProt,
                    &oldCodeProt);
            }

            // mark this thread as "inside" this protected fn
            g_tls_stack.push_back(&e);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ------------------------------------------------------------
// EnsureVEHInstalled
// ------------------------------------------------------------
__declspec(noinline) inline void EnsureVEHInstalled() {
    bool expected = false;
    if (g_handlerReady.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        ::AddVectoredExceptionHandler(1, &VEHDecryptionHandler);
    }
}

// ------------------------------------------------------------
// AnalyzeFunctionForEndSED
// Scan forward until CALL/JMP EndSED is found. Cap 64KB to avoid runaway.
// NOTE: if the body is *extremely* tiny, some builds can tailcall/jmp EndSED
// in a way that still hits our pattern. If FunctionSize ends up 0 here, that
// function won't rotate stash (clone_stash_and_rotate() early-outs on sz==0).
// We pad testFast() in tests so size > 0.
//
// We use VirtualQuery() to make sure we don't walk into an
// invalid/unmapped page. This prevents accidental AV if someone passes an
// arbitrary address to EncryptFunction() that spans multiple regions.
// ------------------------------------------------------------
__declspec(noinline) inline bool AnalyzeFunctionForEndSED(uintptr_t fn, EncryptedFunctionEntry& out) {
    unsigned char* p = reinterpret_cast<unsigned char*>(fn);
    int size = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T qres = ::VirtualQuery(p, &mbi, sizeof(mbi));
    if (qres != sizeof(mbi))
        return false;

    // Limit scan to at most 64KB OR current region size, whichever is smaller.
    const SIZE_T region_remaining =
        (reinterpret_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize) - p;
    const int maxScan = static_cast<int>(
        (region_remaining < 0x10000 ? region_remaining : 0x10000));

    while (size < maxScan) {
        unsigned char op = *p;

        if (op == 0xE8 || op == 0xE9) { // CALL or JMP rel32
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
// Install VEH if needed, append new entry, stash encrypted bytes in
// private VA (RO), wipe live code with UD2/junk so first call faults.
// ------------------------------------------------------------
__declspec(noinline) inline void EncryptFunction(uintptr_t functionPointer) {
    EnsureVEHInstalled();

    const size_t oldCount = g_count.load(std::memory_order_acquire);
    EncryptedFunctionEntry* oldTable = g_table.load(std::memory_order_acquire);
    const size_t newCount = oldCount + 1;

    EncryptedFunctionEntry* newTable = static_cast<EncryptedFunctionEntry*>(
        ::HeapAlloc(::GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            newCount * sizeof(EncryptedFunctionEntry)));

    if (!newTable) {
        // Allocation failed -> nothing we can do, leave as-is.
        return;
    }

    if (oldTable && oldCount) {
        std::memcpy(newTable,
            oldTable,
            oldCount * sizeof(EncryptedFunctionEntry));
    }

    EncryptedFunctionEntry& cur = newTable[newCount - 1];
    cur.FunctionAddress = functionPointer;

    if (!AnalyzeFunctionForEndSED(functionPointer, cur)) {
        ::HeapFree(::GetProcessHeap(), 0, newTable);
        return;
    }

    // init per-function wipe RNG
    cur.seed = static_cast<uint64_t>(functionPointer) ^ __rdtsc();

    const size_t sz = static_cast<size_t>(cur.FunctionSize);

    // private stash VA (encrypted at rest, RO at rest)
    unsigned char* stash = static_cast<unsigned char*>(
        ::VirtualAlloc(nullptr,
            sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE));
    if (!stash) {
        ::HeapFree(::GetProcessHeap(), 0, newTable);
        return;
    }

    std::memcpy(stash,
        reinterpret_cast<void*>(cur.FunctionAddress),
        sz);

#if USE_XOR_ENCRYPTION
    xor_crypt(stash, sz); // encrypt stash copy
#endif

    DWORD oldProt;
    ::VirtualProtect(stash,
        sz,
        PAGE_READONLY,
        &oldProt);

    cur.stash.ptr.store(stash, std::memory_order_release);
    cur.stash.generation.store(0, std::memory_order_release);

    // wipe live code so first execution traps into VEH
    WipeLiveCodeSection(reinterpret_cast<LPVOID>(cur.FunctionAddress),
        static_cast<int>(cur.FunctionSize),
        cur.seed);

    // publish new table (We never edit old table in-place)
    g_table.store(newTable, std::memory_order_release);
    g_count.store(newCount, std::memory_order_release);

    // retire old table (if any) with current epoch snapshot
    if (oldTable && oldCount) {
        const uint64_t retireEpoch = g_reclaimEpoch.load(std::memory_order_acquire);
        g_retiredTables.push_back(
            RetiredTable{ oldTable, oldCount, retireEpoch });
    }

    // Advance epoch for this structural mutation, then try to reclaim anything
    // sufficiently old (both retired stashes and retired tables).
    (void)g_reclaimEpoch.fetch_add(1, std::memory_order_acq_rel);
    GlobalReclaim();
}

// ------------------------------------------------------------
// CallFunction (varargs helper for C ABI style fns)
// ------------------------------------------------------------
__declspec(noinline) inline void* CallFunction(void* ptr, ...) {
    va_list ap;
    va_start(ap, ptr);
    void* ret = reinterpret_cast<void* (*)(va_list)>(ptr)(ap);
    va_end(ap);
    return ret;
}