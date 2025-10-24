#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <cstdint>
#include <cstdarg>
#include <atomic>
#include <cstring>
#include <type_traits>
#include <vector>

// ============================================================================
// Configuration / Mode Selection
// ============================================================================
//
// We now support 2 runtime strategies:
//
//   1) SED_MODE_VEH        - Original design.
//      - The protected function body is replaced with illegal opcodes.
//      - Execution of that region triggers EXCEPTION_ILLEGAL_INSTRUCTION.
//      - Our Vectored Exception Handler (VEH) decrypts just-in-time.
//      - Re-encryption happens in EndSED() when the last caller exits.
//      - This is extremely fast but Windows VEH is effectively serialized,
//        so scaling to many threads can stall on the VEH path.
//
//   2) SED_MODE_TRAMPOLINE - Concurrent/JIT-style entry without VEH.
//      - The function body is still encrypted (illegal opcodes).
//      - Before we call the function, CallFunction() explicitly "activates"
//        the function: atomically marks it active, decrypts code if needed,
//        and pushes it on the TLS call stack.
//      - The function then runs normally and calls EndSED() at the end,
//        which decrements ActiveCalls and re-encrypts when it hits 0.
//      - No VEH is involved, so many threads can enter concurrently
//        without handler serialization.
//      - NOTE: In this mode, you MUST invoke the function via CallFunction.
//        Directly calling the raw function pointer will fault, since
//        there is no VEH to decrypt on illegal opcode.
//
// You can pick the mode with SED_MODE below.
//
// ============================================================================

#define SED_MODE_VEH         1
#define SED_MODE_TRAMPOLINE  2

#ifndef SED_MODE
#define SED_MODE SED_MODE_VEH // VEH is default behavior for backward compatibility
#endif

// ---------------------------------------------------------------------------
// Encryption config / debug knobs
// ---------------------------------------------------------------------------

#define USE_XOR_ENCRYPTION 1

// Re-encryption is so fast that debugging / memory inspection is otherwise
// nearly impossible. These are for development / reverse engineering sessions.
#define SED_DEBUG_KEEP_DECRYPTED 0   // when 1, EndSED() will NOT re-encrypt
#define SED_DEBUG_SLEEP 0            // when 1, EndSED() sleeps 5s before re-encrypt

#if USE_XOR_ENCRYPTION
static constexpr unsigned char xor_key[] =
"YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn";
static constexpr size_t xor_key_size = sizeof(xor_key) - 1;
#endif

// ============================================================================
// Internal structures
// ============================================================================
//
// EncryptedFunctionEntry is "published" in an immutable array that gets
// replaced atomically on each EncryptFunction() call. We never free the
// previous array to avoid race conditions with concurrent readers (RCU-like).
//
// ActiveCalls:
//   - Number of *active* threads currently executing the decrypted code.
//   - First thread to bump ActiveCalls 0->1 performs the decrypt.
//   - Last thread to drop ActiveCalls 1->0 (in EndSED) re-encrypts.
//
struct EncryptedFunctionEntry {
    uintptr_t FunctionAddress;              // start of protected code
    uintptr_t ReturnAddress;                // address of call/jmp to EndSED (legacy info)
    int64_t   FunctionSize;                 // length of function in bytes
    unsigned char* originalBytes;           // XOR-encrypted stash of original code
    BOOL      IsJMPReturn;                  // legacy semantic from analyzer
    std::atomic<int> ActiveCalls{ 0 };      // how many threads currently executing
};

// Global function registry (immutable snapshots published atomically)
inline std::atomic<EncryptedFunctionEntry*> g_table{ nullptr };
inline std::atomic<size_t>                 g_count{ 0 };

// Set to true once VEH is installed (VEH mode only)
inline std::atomic<bool> g_handlerReady{ false };

// Thread-local stack of active SED functions so EndSED() knows
// which function this thread is "inside".
thread_local std::vector<EncryptedFunctionEntry*> g_tls_stack;

// ============================================================================
// Forward declarations of helpers / API
// ============================================================================

// Internal: activate (decrypt if first caller, push TLS, bump refcount)
inline void SEDEnter(uintptr_t fnAddr);

// Public API wrappers
template <typename Fn, typename... Args>
inline void* CallFunction(Fn fn, Args... args);

__declspec(noinline) inline void* CallFunction(void* ptr, ...);

// Called at the end of every protected function
__declspec(dllexport) inline void* EndSED(void* returnValue);

// Encrypt/register a function's code region
__declspec(noinline) inline void EncryptFunction(uintptr_t functionPointer);

// Internal pieces we need to reference across modes
__declspec(noinline) inline bool AnalyzeFunctionForEndSED(
    uintptr_t fn,
    EncryptedFunctionEntry& out);

__declspec(noinline) inline void EncryptCodeSection(
    LPVOID address,
    unsigned char* stash,
    int SIZE_OF_FUNCTION);

// VEH path (only compiled/used in VEH mode)
#if SED_MODE == SED_MODE_VEH
__declspec(noinline) inline LONG WINAPI VEHDecryptionHandler(
    PEXCEPTION_POINTERS exceptions);
__declspec(noinline) inline void EnsureVEHInstalled();
#endif

// ============================================================================
// XOR helper for in-memory code bytes
// ============================================================================
#if USE_XOR_ENCRYPTION
inline void xor_crypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= xor_key[i % xor_key_size];
}
#endif

// ============================================================================
// EndSED – executed at the end of every protected function
// ============================================================================
//
// Lifecycle summary:
//   - Caller (either VEH handler in SED_MODE_VEH or SEDEnter() in
//     SED_MODE_TRAMPOLINE) pushes the relevant EncryptedFunctionEntry*
//     into this thread's g_tls_stack and increments ActiveCalls.
//
//   - The protected function eventually calls EndSED(returnValue).
//
//   - EndSED() pops the entry for this frame and decrements ActiveCalls.
//     When ActiveCalls hits 0, we re-encrypt (unless debugging overrides).
//
// Thread-safety:
//   - ActiveCalls is std::atomic<int>, so increments/decrements are safe.
//   - Only the final thread (ActiveCalls becomes 0) rewrites code bytes,
//     so we never re-encrypt while another thread is still executing.
//   - Memory barriers are acq_rel to ensure visibility/order.
//
#pragma optimize("", off)
__declspec(dllexport) inline void* EndSED(void* returnValue) {
    if (!g_tls_stack.empty()) {
        EncryptedFunctionEntry* e = g_tls_stack.back();
        g_tls_stack.pop_back();

        const int remaining =
            e->ActiveCalls.fetch_sub(1, std::memory_order_acq_rel) - 1;

        if (remaining == 0) {
#if SED_DEBUG_SLEEP
            ::Sleep(5000);
#endif
#if !SED_DEBUG_KEEP_DECRYPTED
            // Re-encrypt/wipe the live code region so that future calls will
            // either fault into the VEH handler (VEH mode) or force a fresh
            // decrypt via SEDEnter (TRAMPOLINE mode).
            DWORD oldProtect;
            ::VirtualProtect(
                reinterpret_cast<LPVOID>(e->FunctionAddress),
                static_cast<SIZE_T>(e->FunctionSize),
                PAGE_EXECUTE_READWRITE,
                &oldProtect);

#   if defined(_WIN64)
            std::memset(
                reinterpret_cast<void*>(e->FunctionAddress),
                0x1F,
                static_cast<size_t>(e->FunctionSize));
#   else
            std::memset(
                reinterpret_cast<void*>(e->FunctionAddress),
                0xFE,
                static_cast<size_t>(e->FunctionSize));
#   endif

            ::FlushInstructionCache(
                ::GetCurrentProcess(),
                reinterpret_cast<void*>(e->FunctionAddress),
                static_cast<SIZE_T>(e->FunctionSize));

            ::VirtualProtect(
                reinterpret_cast<LPVOID>(e->FunctionAddress),
                static_cast<SIZE_T>(e->FunctionSize),
                oldProtect,
                &oldProtect);
#endif // !SED_DEBUG_KEEP_DECRYPTED
        }
    }
    return returnValue;
}
#pragma optimize("", on)

// ============================================================================
// EncryptCodeSection – initial setup
// ============================================================================
//
// 1. Copy original function bytes into 'stash' and immediately encrypt them.
// 2. Overwrite the live code region with illegal opcodes (0x1F on x64,
//    0xFE on x86) so any attempt to execute will fault / be invalid
//    until we explicitly decrypt.
// 3. Flush CPU instruction cache.
//
// After this runs, the only valid way to execute the function is through
// our controlled entry path (VEH or SEDEnter).
//
__declspec(noinline) inline void EncryptCodeSection(
    LPVOID address,
    unsigned char* stash,
    int SIZE_OF_FUNCTION)
{
    // Keep an encrypted backup of the real code
    std::memcpy(stash, address, SIZE_OF_FUNCTION);

#if USE_XOR_ENCRYPTION
    xor_crypt(stash, SIZE_OF_FUNCTION); // now 'stash' is encrypted
#endif

    DWORD oldProtect;
    ::VirtualProtect(
        address,
        SIZE_OF_FUNCTION,
        PAGE_EXECUTE_READWRITE,
        &oldProtect);

#if defined(_WIN64)
    std::memset(address, 0x1F, SIZE_OF_FUNCTION);
#else
    std::memset(address, 0xFE, SIZE_OF_FUNCTION);
#endif

    ::FlushInstructionCache(::GetCurrentProcess(), address, SIZE_OF_FUNCTION);

    ::VirtualProtect(
        address,
        SIZE_OF_FUNCTION,
        oldProtect,
        &oldProtect);
}

// ============================================================================
// Internal helper: Find a function's registry entry
// ============================================================================
//
// Linear search over the immutable snapshot table. g_table/g_count are only
// appended to (new snapshot published atomically); old snapshots are never
// freed, so concurrent readers are safe.
//
inline EncryptedFunctionEntry* FindEntry(uintptr_t fnAddr) {
    auto* table = g_table.load(std::memory_order_acquire);
    const size_t count = g_count.load(std::memory_order_acquire);
    if (!table || count == 0) return nullptr;

    for (size_t i = 0; i < count; ++i) {
        auto& e = table[i];
        if (e.FunctionAddress == fnAddr)
            return &e;
    }
    return nullptr;
}

// ============================================================================
// Internal helper: perform "activation" of a function
// ============================================================================
//
// This is the heart of both modes:
//
//  - Increment ActiveCalls.
//  - If this is the first active caller (prev == 0), decrypt live bytes.
//  - Push this entry onto the thread-local stack so EndSED() knows
//    which function to finish/re-encrypt on return.
//
// In VEH mode this logic runs inside VEHDecryptionHandler, which is triggered
// by the illegal opcode fault. In TRAMPOLINE mode this logic runs from
// CallFunction() *before* we actually invoke the target function.
//
inline void ActivateFunctionEntry(EncryptedFunctionEntry& e) {
    const int prev = e.ActiveCalls.fetch_add(1, std::memory_order_acq_rel);
    if (prev == 0) {
        // First live caller: decrypt actual code bytes into executable memory.
        DWORD oldProtect;
        ::VirtualProtect(
            reinterpret_cast<LPVOID>(e.FunctionAddress),
            static_cast<SIZE_T>(e.FunctionSize),
            PAGE_EXECUTE_READWRITE,
            &oldProtect);

#if USE_XOR_ENCRYPTION
        // Decrypt the stash into plaintext bytes, copy to live code,
        // then immediately re-encrypt the stash in-place so we never
        // leave an extra plaintext copy around.
        xor_crypt(e.originalBytes,
            static_cast<size_t>(e.FunctionSize)); // -> plaintext
#endif

        std::memcpy(
            reinterpret_cast<void*>(e.FunctionAddress),
            e.originalBytes,
            static_cast<size_t>(e.FunctionSize));

        ::FlushInstructionCache(
            ::GetCurrentProcess(),
            reinterpret_cast<void*>(e.FunctionAddress),
            static_cast<SIZE_T>(e.FunctionSize));

#if USE_XOR_ENCRYPTION
        xor_crypt(e.originalBytes,
            static_cast<size_t>(e.FunctionSize)); // back to encrypted
#endif

        ::VirtualProtect(
            reinterpret_cast<LPVOID>(e.FunctionAddress),
            static_cast<SIZE_T>(e.FunctionSize),
            oldProtect,
            &oldProtect);
    }

    // Track on this thread's logical call stack so EndSED() can find us.
    g_tls_stack.push_back(&e);
}

// ============================================================================
// SEDEnter – entry hook for TRAMPOLINE mode
// ============================================================================
//
// In TRAMPOLINE mode, there is no VEH to intercept the illegal instruction.
// Instead, CallFunction() calls SEDEnter() with the target function's address
// *before* actually invoking it. SEDEnter() finds the metadata and
// ActivateFunctionEntry().
//
// In VEH mode this still exists, but CallFunction() won't call it.
//
inline void SEDEnter(uintptr_t fnAddr) {
#if SED_MODE == SED_MODE_TRAMPOLINE
    if (EncryptedFunctionEntry* e = FindEntry(fnAddr)) {
        ActivateFunctionEntry(*e);
    }
#else
    (void)fnAddr; // suppress unused warning in VEH mode
#endif
}

// ============================================================================
// VEHDecryptionHandler – runtime decryption trap (VEH mode only)
// ============================================================================
//
// Triggered by EXCEPTION_ILLEGAL_INSTRUCTION when a thread tries to execute an
// encrypted function. We identify which function faulted, run the same
// ActivateFunctionEntry() logic as TRAMPOLINE mode, and then continue execution
// at the now-decrypted address.
//
// This is inherently serialized by Windows VEH dispatching, which is why
// high thread counts can bottleneck here. But it's extremely fast otherwise.
//
#if SED_MODE == SED_MODE_VEH
__declspec(noinline) inline LONG WINAPI VEHDecryptionHandler(
    PEXCEPTION_POINTERS exceptions)
{
    const auto code = exceptions->ExceptionRecord->ExceptionCode;
    auto* table = g_table.load(std::memory_order_acquire);
    const size_t count = g_count.load(std::memory_order_acquire);
    if (!table || count == 0)
        return EXCEPTION_CONTINUE_SEARCH;

    if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        const auto faultIP =
            reinterpret_cast<uintptr_t>(
                exceptions->ExceptionRecord->ExceptionAddress);

        for (size_t i = 0; i < count; ++i) {
            auto& e = table[i];
            if (faultIP == e.FunctionAddress) {
                // Same core logic as TRAMPOLINE mode:
                ActivateFunctionEntry(e);

                // Resume execution at the now-decrypted code.
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
#endif // SED_MODE == SED_MODE_VEH

// ============================================================================
// VEH installation (VEH mode only)
// ============================================================================
#if SED_MODE == SED_MODE_VEH
__declspec(noinline) inline void EnsureVEHInstalled() {
    bool expected = false;
    if (g_handlerReady.compare_exchange_strong(
        expected,
        true,
        std::memory_order_acq_rel))
    {
        ::AddVectoredExceptionHandler(1, &VEHDecryptionHandler);
    }
}
#endif // SED_MODE == SED_MODE_VEH

// ============================================================================
// AnalyzeFunctionForEndSED
// ============================================================================
//
// Scans forward from 'fn' until it finds a relative CALL/JMP to EndSED.
// That point marks the logical end of the protected region, and we record
// the size in bytes so we know how much to encrypt/decrypt.
//
// NOTE: This is heuristic, like the original PoC. It's assuming that the
// first direct CALL/JMP to EndSED marks the logical end of the function's
// "sensitive region" that we want to encrypt. We retain legacy fields
// (IsJMPReturn, ReturnAddress) even if we don't strictly need them in the
// new mode.
//
__declspec(noinline) inline bool AnalyzeFunctionForEndSED(
    uintptr_t fn,
    EncryptedFunctionEntry& out)
{
    unsigned char* p = reinterpret_cast<unsigned char*>(fn);
    int size = 0;
    while (true) {
        unsigned char op = *p;

        // 0xE8 = CALL rel32, 0xE9 = JMP rel32
        if (op == 0xE8 || op == 0xE9) {
            auto rel = *reinterpret_cast<const int32_t*>(p + 1);
            uintptr_t target =
                reinterpret_cast<uintptr_t>(p + 5) + rel;

            if (target == reinterpret_cast<uintptr_t>(&EndSED)) {
                out.IsJMPReturn = (op == 0xE9);
                out.ReturnAddress = reinterpret_cast<uintptr_t>(p);
                out.FunctionSize = size;
                return true;
            }
        }

        ++p;
        ++size;

        // Safety guard in case of malformed function (no EndSED found)
        if (size > 0x10000)
            return false;
    }
}

// ============================================================================
// EncryptFunction – registers and encrypts a new function
// ============================================================================
//
// Steps:
//   1. (VEH mode only) Ensure VEH handler is installed.
//   2. Publish a new immutable table containing metadata for this function.
//   3. Analyze function to locate EndSED and compute length to protect.
//   4. Copy plaintext bytes into e.originalBytes (allocated with HeapAlloc).
//      Immediately XOR-encrypt that stash.
//   5. Overwrite the live function bytes in memory with illegal opcodes.
//
// After this point, calling this function "normally" would raise
// EXCEPTION_ILLEGAL_INSTRUCTION (or just execute garbage), so you MUST
// enter via CallFunction() (TRAMPOLINE mode) or rely on VEH (VEH mode).
//
__declspec(noinline) inline void EncryptFunction(uintptr_t functionPointer) {

#if SED_MODE == SED_MODE_VEH
    // VEH mode needs the vectored exception handler installed exactly once.
    EnsureVEHInstalled();
#endif

    // Snapshot current table
    const size_t oldCount =
        g_count.load(std::memory_order_acquire);
    EncryptedFunctionEntry* oldTable =
        g_table.load(std::memory_order_acquire);

    const size_t newCount = oldCount + 1;

    // Allocate a new enlarged table
    EncryptedFunctionEntry* newTable =
        static_cast<EncryptedFunctionEntry*>(
            ::HeapAlloc(::GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                newCount * sizeof(EncryptedFunctionEntry)));

    // Copy over old entries (RCU-style persistence)
    if (oldTable && oldCount) {
        std::memcpy(newTable,
            oldTable,
            oldCount * sizeof(EncryptedFunctionEntry));
    }

    // Fill in the new slot
    EncryptedFunctionEntry& cur = newTable[newCount - 1];
    cur.FunctionAddress = functionPointer;

    if (!AnalyzeFunctionForEndSED(functionPointer, cur)) {
        // Failed to parse -> cleanup and bail out
        ::HeapFree(::GetProcessHeap(), 0, newTable);
        return;
    }

    // Allocate stash for encrypted original bytes
    cur.originalBytes = static_cast<unsigned char*>(
        ::HeapAlloc(::GetProcessHeap(),
            0,
            cur.FunctionSize));

    std::memcpy(
        cur.originalBytes,
        reinterpret_cast<void*>(cur.FunctionAddress),
        cur.FunctionSize);

#if USE_XOR_ENCRYPTION
    // Encrypt the stash in-place
    xor_crypt(cur.originalBytes,
        static_cast<size_t>(cur.FunctionSize));
#endif

    // Overwrite live code with illegal opcodes so it's not executable
    EncryptCodeSection(
        reinterpret_cast<LPVOID>(cur.FunctionAddress),
        cur.originalBytes,
        static_cast<int>(cur.FunctionSize));

    // Publish the new immutable snapshot (no free of oldTable to avoid races)
    g_table.store(newTable, std::memory_order_release);
    g_count.store(newCount, std::memory_order_release);
}

// ============================================================================
// CallFunction (templated) – public entry point for protected code
// ============================================================================
//
// Usage pattern is unchanged from the original library. You still call
//   CallFunction(targetFn, args...);
//
// Behavior by mode:
//
//   - SED_MODE_VEH:
//       We just directly invoke the function pointer. The first instruction
//       is an illegal opcode, which triggers VEHDecryptionHandler(), which
//       will decrypt, bump ActiveCalls, push TLS, then resume execution
//       inside the function. EndSED() will re-encrypt when done.
//
//   - SED_MODE_TRAMPOLINE:
//       No VEH will run. Instead we explicitly "enter" the function here:
//         * lookup the function's metadata
//         * decrypt-if-needed
//         * push TLS / bump ActiveCalls
//       Then we call the now-decrypted body. The function will eventually
//       execute EndSED() to pop TLS, decrement ActiveCalls, and possibly
//       re-encrypt.
//
// Thread safety:
//   - ActivateFunctionEntry() uses atomic increments/decrements.
//   - Multiple threads can concurrently call CallFunction() on the same
//     protected function without serializing through VEH.
//
template <typename Fn, typename... Args>
inline void* CallFunction(Fn fn, Args... args) {
#if SED_MODE == SED_MODE_TRAMPOLINE
    SEDEnter(reinterpret_cast<uintptr_t>(fn));
#endif

    return reinterpret_cast<void* (__cdecl*)(void*, Args...)>(fn)(
        nullptr,
        std::forward<Args>(args)...);
}

// ============================================================================
// CallFunction (varargs) – C-style/va_list helper
// ============================================================================
//
// Same semantics as the templated overload, but takes a single void* and
// assumes the callee is of signature  void* f(va_list).
//
__declspec(noinline) inline void* CallFunction(void* ptr, ...) {
#if SED_MODE == SED_MODE_TRAMPOLINE
    SEDEnter(reinterpret_cast<uintptr_t>(ptr));
#endif

    va_list ap;
    va_start(ap, ptr);

    void* ret = reinterpret_cast<void* (*)(va_list)>(ptr)(ap);

    va_end(ap);
    return ret;
}