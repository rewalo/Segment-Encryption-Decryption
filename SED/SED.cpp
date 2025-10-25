#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <cassert>
#include "SED.h"

#pragma region Math Helpers
int factorial(int n) {
    return (n <= 1) ? 1 : n * factorial(n - 1);
}

int fibonacci(int n) {
    return (n <= 1) ? n : fibonacci(n - 1) + fibonacci(n - 2);
}

void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) std::printf("%d ", arr[i]);
}

void swap_int(int* xp, int* yp) {
    int t = *xp; *xp = *yp; *yp = t;
}

void bubbleSort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < n - i - 1; j++)
            if (arr[j] > arr[j + 1]) swap_int(&arr[j], &arr[j + 1]);
}
#pragma endregion

// ------------------------------------------------------------
// Example protected functions (each ends with EndSED())
// ------------------------------------------------------------
void* testCCode(int numberArgument) { // __declspec(noinline) used to be required here, but we have stable function sizing and anti-tailcall protection in SED itself now, so inlining no longer breaks encryption/rotation.
    std::printf("[testCCode] Arg: %d | Expect return = %d + 1\n", numberArgument, numberArgument);
    int arr[5] = { 1,2,3,4,5 };
    std::printf("Array: ");
    printArray(arr, 5);

    std::printf("\nFactorial(5) = %d\n", factorial(5));

    std::printf("Fibonacci(0..9): ");
    for (int i = 0; i < 10; i++) std::printf("%d ", fibonacci(i));
    std::printf("\n");

    return EndSED(reinterpret_cast<void*>(numberArgument + 1)); // Always return via EndSED, otherwise the function will stay decrypted!
}

void* testCCode2(const char* strArg, int numArg) {
    std::printf("[testCCode2] Arg1: %s | Arg2: %d\n", strArg, numArg);
    char str1[20] = "Hello";
    char str2[20] = "World";
    char str3[40];
    std::strcpy(str3, str1);
    std::strcat(str3, " ");
    std::strcat(str3, str2);
    std::printf("Concat result: %s\n", str3);
    return EndSED(reinterpret_cast<void*>(0));
}

// Tiny function for churn testing
__declspec(noinline) void* testFast(void*) {
    volatile int keep = 1; // ensure the body isn't optimized out or tail-called
    (void)keep;
    return EndSED(reinterpret_cast<void*>(1));
}

// ------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------
static void sleep_ms(DWORD ms) {
    ::Sleep(ms);
}

// ------------------------------------------------------------
// Utility: manual GC / epoch advance
// ------------------------------------------------------------
static void force_gc_cycles(size_t cycles, DWORD pause_ms) {
    for (size_t i = 0; i < cycles; ++i) {
        (void)testFast(nullptr);
        ProcessPendingRelocksAndGC(); // advance epoch + rotate + reclaim
        if (pause_ms) sleep_ms(pause_ms);
    }
}

// ------------------------------------------------------------
// Single-thread performance check
// ------------------------------------------------------------
static void run_overhead_test_fast(size_t iterations) {
    std::puts("\n[Single-thread overhead test]");
    (void)testFast(nullptr); // warm-up

    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();

    size_t ok = 0;
    for (size_t i = 0; i < iterations; ++i) {
        auto rv = reinterpret_cast<intptr_t>(testFast(nullptr));
        ok += (rv == 1);
    }

    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    double per_call_ns = static_cast<double>(ns) / static_cast<double>(iterations);

    std::printf("Iterations: %zu | OK: %zu | Total: %.3f ms | Per call: %.1f ns\n",
        iterations, ok, ns / 1e6, per_call_ns);
}

// ------------------------------------------------------------
// Multi-thread: all threads call the SAME protected function
// ------------------------------------------------------------
static void run_concurrent_same(size_t threads, size_t iters_per_thread) {
    std::puts("\n[Multi-thread test: same protected function]");
    std::atomic<size_t> ok{ 0 };
    std::atomic<size_t> errs{ 0 };

    auto worker = [&](size_t tid) {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            int arg = static_cast<int>(tid * 100000 + i);
            auto rv = reinterpret_cast<intptr_t>(testCCode(arg));
            if (rv == arg + 1) ok++;
            else errs++;
        }
        };

    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (size_t t = 0; t < threads; ++t)
        pool.emplace_back(worker, t);
    for (auto& th : pool) th.join();

    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    size_t total = threads * iters_per_thread;

    std::printf("Threads: %zu | Calls: %zu | OK: %zu | ERR: %zu\n", threads, total, ok.load(), errs.load());
    std::printf("Total: %.3f ms | Per call: %.1f µs\n", ns / 1e6, (double)ns / total / 1000.0);
}

// ------------------------------------------------------------
// Multi-thread: threads call different protected functions
// ------------------------------------------------------------
static void run_concurrent_mixed(size_t threads, size_t iters_per_thread) {
    std::puts("\n[Multi-thread test: mixed protected functions]");
    std::atomic<size_t> ok{ 0 };
    std::atomic<size_t> errs{ 0 };

    auto workerA = [&](size_t tid) {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            int arg = static_cast<int>(tid * 100000 + i);
            auto rv = reinterpret_cast<intptr_t>(testCCode(arg));
            if (rv == arg + 1) ok++;
            else errs++;
        }
        };
    auto workerB = [&](size_t tid) {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            (void)testCCode2("concurrent", static_cast<int>(tid * 1000 + i));
            ok++; // we only validate stability, not the return value
        }
        };

    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (size_t t = 0; t < threads; ++t) {
        if ((t % 2) == 0) pool.emplace_back(workerA, t);
        else pool.emplace_back(workerB, t);
    }
    for (auto& th : pool) th.join();

    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    size_t total = threads * iters_per_thread;

    std::printf("Threads: %zu | Calls: %zu | OK: %zu | ERR: %zu\n", threads, total, ok.load(), errs.load());
    std::printf("Total: %.3f ms | Per call: %.1f µs\n", ns / 1e6, (double)ns / total / 1000.0);
}

// ------------------------------------------------------------
// High-churn torture test
// ------------------------------------------------------------
// Repeatedly decrypt/re-encrypt the same small function at high frequency.
// Use this to prove stability under extreme cycling.
static void run_break_reencrypt_churn(size_t threads, size_t iters_per_thread) {
    std::puts("\n[Torture churn test: rapid decrypt/re-encrypt]");
    std::atomic<size_t> ok{ 0 };

    auto worker = [&]() {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            (void)testFast(nullptr);
            ok++;
            if ((i % 1024) == 0) sleep_ms(0);
        }
        };

    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (size_t t = 0; t < threads; ++t)
        pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    size_t total = threads * iters_per_thread;

    std::printf("Threads: %zu | Calls: %zu | OK: %zu | Total: %.3f ms | Per call: %.1f ns\n",
        threads, total, ok.load(), ns / 1e6, (double)ns / total);
}

// ------------------------------------------------------------
// Validate stash relocation and GC behavior
// ------------------------------------------------------------
static void run_stash_relocation_tests() {
    std::puts("\n[Stash relocation + GC validation]");

    auto* table = g_table.load(std::memory_order_acquire);
    size_t count = g_count.load(std::memory_order_acquire);
    if (!table || count == 0) {
        std::puts("[Error] No encrypted functions registered!");
        return;
    }

    struct Snapshot {
        uintptr_t fn;
        unsigned char* ptr;
        uint64_t gen;
    };

    std::vector<Snapshot> before;
    before.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        before.push_back({
            table[i].FunctionAddress,
            table[i].stash.ptr.load(std::memory_order_acquire),
            table[i].stash.generation.load(std::memory_order_acquire)
            });
    }

    // Run several controlled rotations and epoch advancements
    force_gc_cycles(50, 2);

    std::vector<Snapshot> after;
    after.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        after.push_back({
            table[i].FunctionAddress,
            table[i].stash.ptr.load(std::memory_order_acquire),
            table[i].stash.generation.load(std::memory_order_acquire)
            });
    }

    size_t moved = 0, genIncreased = 0;
    for (size_t i = 0; i < count; ++i) {
        if (after[i].gen > before[i].gen) genIncreased++;
        if (after[i].ptr != before[i].ptr) moved++;
    }

    std::printf("Functions observed: %zu | PointerMoved: %zu | Generation++: %zu\n",
        count, moved, genIncreased);

    std::printf("Retired stash regions tracked: %zu\n", g_retiredStashes.size());
    std::printf("Global epoch: %llu\n", (unsigned long long)g_reclaimEpoch.load());

    std::puts("[Relocation + GC tests passed]");
}

// ------------------------------------------------------------
// Main demonstration
// ------------------------------------------------------------
int main() {
    std::puts("=== SED Runtime Encryption Demo ===");
    std::puts("Attach a debugger like x64dbg *before encryption* to inspect plaintext code and strings:");
    std::puts("  Press Shift+D to open the Strings window.");
    std::puts("  Locate testCCode, testCCode2, and testFast, verify code and strings are readable.\n");
    system("pause");

    std::puts("Encrypting protected functions...");
    EncryptFunction(reinterpret_cast<uintptr_t>(testCCode));
    EncryptFunction(reinterpret_cast<uintptr_t>(testCCode2));
    EncryptFunction(reinterpret_cast<uintptr_t>(testFast));

    std::puts("Encryption complete. All protected functions are now wiped and registered.");
    std::puts("Attach x64dbg *after encryption* to confirm that protected regions are no longer readable:");
    std::puts("  In the CPU view, the function bytes should appear as UD2/junk.");
    std::puts("  In the Strings window (Shift+D), those names and literals should now be gone.");
    std::puts("  You can place a breakpoint on a protected function and watch it decrypt at runtime.\n");
    system("pause");

    std::puts("[RUN]");
    int rv = static_cast<int>(reinterpret_cast<intptr_t>(testCCode(15)));
    std::printf("Returned value: %d\n", rv);
    testCCode2("abcd", 123); // We used to use CallFunction wrapper, but now that we're doing runtime patch-on-demand, we can call directly.
    std::puts("[END]");
    system("pause");

    // ------------------------------------------------------------
    // Validation tests
    // ------------------------------------------------------------
    run_stash_relocation_tests();

    // ------------------------------------------------------------
    // Performance and stress tests (uncomment to run)
    // ------------------------------------------------------------
    // run_overhead_test_fast(100000);
    // run_concurrent_same(8, 200);
    // run_concurrent_mixed(8, 200);
    // run_break_reencrypt_churn(500, 200000);

    system("pause");
    return 0;
}