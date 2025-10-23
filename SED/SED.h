#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <cstdint>
#include <cstdarg>
#include <atomic>
#include <cstring>
#include <type_traits>
#include <vector>

// =========================
// Configuration / Key
// =========================
#define USE_XOR_ENCRYPTION 1

// The re-encryption is actually so fast, we have to either simulate delay or disable re-encryption entirely to see interleaving in tests.
#define SED_DEBUG_KEEP_DECRYPTED 0      // when 1, EndSED() will NOT re-encrypt at exit
#define SED_DEBUG_SLEEP 1               // when 1, add a short Sleep() so you can attach or inspect

#if USE_XOR_ENCRYPTION
static constexpr unsigned char xor_key[] = "YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn";
static constexpr size_t xor_key_size = sizeof(xor_key) - 1;
#endif

// =========================
// Public API
// =========================
template <typename Fn, typename... Args>
inline void* CallFunction(Fn fn, Args... args) {
    return reinterpret_cast<void* (__cdecl*)(void*, Args...)>(fn)(
        nullptr, std::forward<Args>(args)...);
}

__declspec(noinline) void* CallFunction(void* ptr, ...);
__declspec(dllexport) void* EndSED(void* returnValue);
__declspec(noinline) void EncryptFunction(uintptr_t functionPointer);

// =========================
// Internal structures
// =========================
struct EncryptedFunctionEntry {
    uintptr_t FunctionAddress;              // start of protected code
    uintptr_t ReturnAddress;                // call/jmp to EndSED inside the function
    int64_t   FunctionSize;                 // size of the function (bytes)
    unsigned char* originalBytes;           // XOR-encrypted copy of original code
    BOOL      IsJMPReturn;                  // kept for legacy logic
    std::atomic<int> ActiveCalls{ 0 };      // how many threads currently executing
};

inline std::atomic<EncryptedFunctionEntry*> g_table{ nullptr };
inline std::atomic<size_t> g_count{ 0 };
inline std::atomic<bool> g_handlerReady{ false };

// Thread-local call stack so EndSED knows which function to close out
thread_local std::vector<EncryptedFunctionEntry*> g_tls_stack;

// ==========================================================
// EndSED – executed at the end of every protected function
// ==========================================================
// Pops the current function from the TLS stack and, when the last
// concurrent caller exits, re-encrypts the code region so any new call
// will fault again and trigger the VEH decryption handler.
#pragma optimize("", off)
__declspec(dllexport) inline void* EndSED(void* returnValue) {
    if (!g_tls_stack.empty()) {
        EncryptedFunctionEntry* e = g_tls_stack.back();
        g_tls_stack.pop_back();

        const int remaining = e->ActiveCalls.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
#if SED_DEBUG_SLEEP
            // Give you time to attach and examine memory before wipe
            ::Sleep(5000);
#endif
#if !SED_DEBUG_KEEP_DECRYPTED
            // Wipe the code region again so the next entry faults
            DWORD oldProtect;
            ::VirtualProtect(reinterpret_cast<LPVOID>(e->FunctionAddress),
                static_cast<SIZE_T>(e->FunctionSize),
                PAGE_EXECUTE_READWRITE, &oldProtect);
#   if defined(_WIN64)
            std::memset(reinterpret_cast<void*>(e->FunctionAddress), 0x1F,
                static_cast<size_t>(e->FunctionSize));
#   else
            std::memset(reinterpret_cast<void*>(e->FunctionAddress), 0xFE,
                static_cast<size_t>(e->FunctionSize));
#   endif
            ::FlushInstructionCache(::GetCurrentProcess(),
                reinterpret_cast<void*>(e->FunctionAddress),
                static_cast<SIZE_T>(e->FunctionSize));
            ::VirtualProtect(reinterpret_cast<LPVOID>(e->FunctionAddress),
                static_cast<SIZE_T>(e->FunctionSize),
                oldProtect, &oldProtect);
#endif
        }
    }
    return returnValue;
}
#pragma optimize("", on)

// ==========================================================
// XOR helper
// ==========================================================
#if USE_XOR_ENCRYPTION
inline void xor_crypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        data[i] ^= xor_key[i % xor_key_size];
}
#endif

// ==========================================================
// EncryptCodeSection – initial setup phase
// ==========================================================
// 1. Copy original function bytes to 'stash' and encrypt them
// 2. Overwrite live code with illegal opcodes (0x1F / 0xFE)
// 3. Flush CPU instruction cache so execution will fault next time
__declspec(noinline) inline void EncryptCodeSection(LPVOID address,
    unsigned char* stash,
    int SIZE_OF_FUNCTION) {
    std::memcpy(stash, address, SIZE_OF_FUNCTION);
#if USE_XOR_ENCRYPTION
    xor_crypt(stash, SIZE_OF_FUNCTION);
#endif
    DWORD oldProtect;
    ::VirtualProtect(address, SIZE_OF_FUNCTION, PAGE_EXECUTE_READWRITE, &oldProtect);
#if defined(_WIN64)
    std::memset(address, 0x1F, SIZE_OF_FUNCTION);
#else
    std::memset(address, 0xFE, SIZE_OF_FUNCTION);
#endif
    ::FlushInstructionCache(::GetCurrentProcess(), address, SIZE_OF_FUNCTION);
    ::VirtualProtect(address, SIZE_OF_FUNCTION, oldProtect, &oldProtect);
}

// ==========================================================
// VEHDecryptionHandler – runtime decryption trap
// ==========================================================
// Triggered by EXCEPTION_ILLEGAL_INSTRUCTION when an encrypted
// function is executed.  Decrypts the code, increments ActiveCalls,
// and lets execution continue.  Re-encryption happens later in EndSED.
__declspec(noinline) inline LONG WINAPI VEHDecryptionHandler(PEXCEPTION_POINTERS exceptions) {
    const auto code = exceptions->ExceptionRecord->ExceptionCode;
    auto* table = g_table.load(std::memory_order_acquire);
    const size_t count = g_count.load(std::memory_order_acquire);
    if (!table || count == 0) return EXCEPTION_CONTINUE_SEARCH;

    if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        const auto faultIP = reinterpret_cast<uintptr_t>(exceptions->ExceptionRecord->ExceptionAddress);
        for (size_t i = 0; i < count; ++i) {
            auto& e = table[i];
            if (faultIP == e.FunctionAddress) {
                const int prev = e.ActiveCalls.fetch_add(1, std::memory_order_acq_rel);
                if (prev == 0) {
                    DWORD oldProtect;
                    ::VirtualProtect(reinterpret_cast<LPVOID>(e.FunctionAddress),
                        static_cast<SIZE_T>(e.FunctionSize),
                        PAGE_EXECUTE_READWRITE, &oldProtect);
#if USE_XOR_ENCRYPTION
                    xor_crypt(e.originalBytes, static_cast<size_t>(e.FunctionSize)); // decrypt
#endif
                    std::memcpy(reinterpret_cast<void*>(e.FunctionAddress),
                        e.originalBytes, static_cast<size_t>(e.FunctionSize));
                    ::FlushInstructionCache(::GetCurrentProcess(),
                        reinterpret_cast<void*>(e.FunctionAddress),
                        static_cast<SIZE_T>(e.FunctionSize));
#if USE_XOR_ENCRYPTION
                    xor_crypt(e.originalBytes, static_cast<size_t>(e.FunctionSize)); // re-encrypt stash
#endif
                    ::VirtualProtect(reinterpret_cast<LPVOID>(e.FunctionAddress),
                        static_cast<SIZE_T>(e.FunctionSize), oldProtect, &oldProtect);
                }
                // Track which function this thread is inside
                g_tls_stack.push_back(&e);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ==========================================================
// VEH installation
// ==========================================================
__declspec(noinline) inline void EnsureVEHInstalled() {
    bool expected = false;
    if (g_handlerReady.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        ::AddVectoredExceptionHandler(1, &VEHDecryptionHandler);
    }
}

// ==========================================================
// AnalyzeFunctionForEndSED – scans a function to find the call/jmp to EndSED and determine where it ends and how big it is.
// ==========================================================
__declspec(noinline) inline bool AnalyzeFunctionForEndSED(uintptr_t fn, EncryptedFunctionEntry& out) {
    unsigned char* p = reinterpret_cast<unsigned char*>(fn);
    int size = 0;
    while (true) {
        unsigned char op = *p;
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
        if (size > 0x10000) return false;
    }
}

// ==========================================================
// EncryptFunction – registers and encrypts a new function (obviously?)
// ==========================================================
__declspec(noinline) inline void EncryptFunction(uintptr_t functionPointer) {
    EnsureVEHInstalled();

    const size_t oldCount = g_count.load(std::memory_order_acquire);
    EncryptedFunctionEntry* oldTable = g_table.load(std::memory_order_acquire);
    const size_t newCount = oldCount + 1;
    EncryptedFunctionEntry* newTable = static_cast<EncryptedFunctionEntry*>(
        ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, newCount * sizeof(EncryptedFunctionEntry)));

    if (oldTable && oldCount)
        std::memcpy(newTable, oldTable, oldCount * sizeof(EncryptedFunctionEntry));

    EncryptedFunctionEntry& cur = newTable[newCount - 1];
    cur.FunctionAddress = functionPointer;

    if (!AnalyzeFunctionForEndSED(functionPointer, cur)) {
        ::HeapFree(::GetProcessHeap(), 0, newTable);
        return;
    }

    cur.originalBytes = static_cast<unsigned char*>(
        ::HeapAlloc(::GetProcessHeap(), 0, cur.FunctionSize));
    std::memcpy(cur.originalBytes, reinterpret_cast<void*>(cur.FunctionAddress),
        cur.FunctionSize);
#if USE_XOR_ENCRYPTION
    xor_crypt(cur.originalBytes, cur.FunctionSize);
#endif

    EncryptCodeSection(reinterpret_cast<LPVOID>(cur.FunctionAddress),
        cur.originalBytes, static_cast<int>(cur.FunctionSize));

    // Publish immutable table; do NOT free old one (avoids race with VEH readers)
    g_table.store(newTable, std::memory_order_release);
    g_count.store(newCount, std::memory_order_release);
}

// ==========================================================
// Var-args CallFunction – helper for C-style entry points
// ==========================================================
__declspec(noinline) inline void* CallFunction(void* ptr, ...) {
    va_list ap;
    va_start(ap, ptr);
    void* ret = reinterpret_cast<void* (*)(va_list)>(ptr)(ap);
    va_end(ap);
    return ret;
}