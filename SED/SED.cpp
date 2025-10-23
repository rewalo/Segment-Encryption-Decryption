#pragma once
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

#pragma region Math Stuff
__declspec(noinline) int factorial(int n) {
    return (n <= 1) ? 1 : n * factorial(n - 1);
}
__declspec(noinline) int fibonacci(int n) {
    return (n <= 1) ? n : fibonacci(n - 1) + fibonacci(n - 2);
}
__declspec(noinline) void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) std::printf("%d ", arr[i]);
}
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
struct Person { char name[50]; int age; };
__declspec(noinline) int gcd(int a, int b) { return (b == 0) ? a : gcd(b, a % b); }
__declspec(noinline) void swap_int(int* xp, int* yp) { int t = *xp; *xp = *yp; *yp = t; }
__declspec(noinline) void bubbleSort(int arr[], int n) {
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < n - i - 1; j++)
            if (arr[j] > arr[j + 1]) swap_int(&arr[j], &arr[j + 1]);
}
#pragma endregion

__declspec(noinline) void* testCCode(void*, int numberArgument) {
    std::printf("Arg 1: %d | Will return %d + 1\n", numberArgument, numberArgument);
    int arr[5] = { 1,2,3,4,5 };
    printArray(arr, 5);
    std::printf("\nFactorial(5): %d\n", factorial(5));
    std::printf("Fibonacci up to 10: ");
    for (int i = 0; i < 10; i++) std::printf("%d ", fibonacci(i));
    std::printf("\n");
    return EndSED(reinterpret_cast<void*>(numberArgument + 1));
}

__declspec(noinline) void* testCCode2(void*, const char* strArg, int numArg) {
    std::printf("Arg1: %s | Arg2: %d\n", strArg, numArg);
    char str1[20] = "Hello";
    char str2[20] = "World";
    char str3[40];
    strcpy(str3, str1);
    strcat(str3, " ");
    strcat(str3, str2);
    std::printf("Concat: %s\n", str3);
    return EndSED(reinterpret_cast<void*>(0));
}

__declspec(noinline) void* testFast(void*) {
    // Minimal body to measure SED decrypt/encrypt overhead without heavy I/O from prints
    return EndSED(reinterpret_cast<void*>(1));
}

// -----------------------------
// Helpers for concurrency tests
// -----------------------------
static void banner(const char* title) {
    std::printf("\n==================== %s ====================\n", title);
}

static void sleep_ms(DWORD ms) {
    ::Sleep(ms);
}

static void run_overhead_test_fast(size_t iterations) {
    banner("Overhead (single-thread, low-noise)");
    // Warm-up to install VEH/decrypt once
    (void)CallFunction(testFast);
    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();
    size_t ok = 0;
    for (size_t i = 0; i < iterations; ++i) {
        auto rv = reinterpret_cast<intptr_t>(CallFunction(testFast));
        ok += (rv == 1);
    }
    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    double per_call_ns = static_cast<double>(ns) / iterations;
    std::printf("Iterations: %zu | OK: %zu | Total: %.3f ms | Per call: %.1f ns\n",
        iterations, ok, ns / 1e6, per_call_ns);
}

static void run_concurrent_same(size_t threads, size_t iters_per_thread) {
    banner("Concurrent stress (same function: testCCode)");
    std::atomic<size_t> ok{ 0 };
    std::atomic<size_t> errs{ 0 };
    auto worker = [&](size_t tid) {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            int arg = static_cast<int>(tid * 100000 + i);
            auto rv = reinterpret_cast<intptr_t>(CallFunction(testCCode, arg));
            if (rv == arg + 1) ok++;
            else errs++;
        }
        };
    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (size_t t = 0; t < threads; ++t) pool.emplace_back(worker, t);
    for (auto& th : pool) th.join();
    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    size_t total = threads * iters_per_thread;
    std::printf("Threads: %zu | Calls: %zu | OK: %zu | ERR: %zu | Total: %.3f ms | Per call: %.1f us\n",
        threads, total, ok.load(), errs.load(), ns / 1e6, (double)ns / total / 1000.0);
}

static void run_concurrent_mixed(size_t threads, size_t iters_per_thread) {
    banner("Concurrent stress (mixed functions: testCCode & testCCode2)");
    std::atomic<size_t> ok{ 0 };
    std::atomic<size_t> errs{ 0 };
    auto workerA = [&](size_t tid) {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            int arg = static_cast<int>(tid * 100000 + i);
            auto rv = reinterpret_cast<intptr_t>(CallFunction(testCCode, arg));
            if (rv == arg + 1) ok++;
            else errs++;
        }
        };
    auto workerB = [&](size_t tid) {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            (void)CallFunction(testCCode2, "concurrent", static_cast<int>(tid * 1000 + i));
            ok++; // no return contract to verify beyond not crashing
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
    std::printf("Threads: %zu | Calls: %zu | OK: %zu | ERR: %zu | Total: %.3f ms | Per call: %.1f us\n",
        threads, total, ok.load(), errs.load(), ns / 1e6, (double)ns / total / 1000.0);
}

static void run_break_reencrypt_churn(size_t threads, size_t iters_per_thread) {
    banner("Churn test (rapid enter/exit causing frequent decrypt/re-encrypt)");
    // Use the minimal function to stress decrypt/encrypt rate without I/O noise.
    std::atomic<size_t> ok{ 0 };
    auto worker = [&]() {
        for (size_t i = 0; i < iters_per_thread; ++i) {
            (void)CallFunction(testFast);
            ok++;
            // brief sleep to increase scheduling interleavings
            if ((i % 1024) == 0) sleep_ms(0);
        }
        };
    using clock = std::chrono::high_resolution_clock;
    auto t0 = clock::now();
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (size_t t = 0; t < threads; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();
    auto t1 = clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    size_t total = threads * iters_per_thread;
    std::printf("Threads: %zu | Calls: %zu | OK: %zu | Total: %.3f ms | Per call: %.1f ns\n",
        threads, total, ok.load(), ns / 1e6, (double)ns / total);
}

int main() {
    std::puts("Encrypting... (Execution will pause once encryption is finished for inspection in x64dbg)");
    EncryptFunction(reinterpret_cast<uintptr_t>(testCCode));
    EncryptFunction(reinterpret_cast<uintptr_t>(testCCode2));
    //EncryptFunction(reinterpret_cast<uintptr_t>(testFast));

    system("pause");

    std::puts("[RUN]");
    int rv = static_cast<int>(reinterpret_cast<intptr_t>(CallFunction(testCCode, 15)));
    std::printf("Return: %d\n", rv);
    CallFunction(testCCode2, "abcd", 123);
    std::puts("[END]");

    system("pause");

    // -----------------------------
    // Thread-safety + overhead tests
    // -----------------------------
    // TestCCode/testCCode2 produce console output; this will interleave under concurrency and significantly affect wall-clock numbers (I/O heavy). For pure overhead timing,
    // use the 'testFast' benchmarks which avoid I/O noise.

    //run_overhead_test_fast(/*iterations*/ 100000);

    //run_concurrent_same(/*threads*/ 8, /*iters_per_thread*/ 200);
    //run_concurrent_mixed(/*threads*/ 8, /*iters_per_thread*/ 200);

    //run_break_reencrypt_churn(/*threads*/ 8, /*iters_per_thread*/ 200);

    //system("pause");

    return 0;
}