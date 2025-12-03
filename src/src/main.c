#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "bloom.h"
#include "tinylfu.h"

#include "utils.h"

void test_bloom(int n) {
    printf("BITS_PER_COUNTER: %lu\n", (unsigned long)BITS_PER_COUNTER);
    printf("SAMPLE_SIZE_BITS: %lu\n", (unsigned long)SAMPLE_SIZE_BITS);
    printf("Testing Bloom Filter with %d elements...\n", n);
    struct bloom *b = bloom_init(n * 10); // 10 bits per element for reasonable false positive rate
    if (!b) {
        printf("Failed to init bloom filter\n");
        return;
    }

    // Add elements
    for (int i = 0; i < n; i++) {
        bloom_add(b, (uint64_t)i);
    }

    // Check contains for added elements
    int false_negatives = 0;
    for (int i = 0; i < n; i++) {
        if (!bloom_contains(b, (uint64_t)i)) {
            false_negatives++;
        }
    }
    if (false_negatives > 0) {
        printf("FAIL: Found %d false negatives (should be 0)\n", false_negatives);
    } else {
        printf("PASS: No false negatives found.\n");
    }

    // Check contains for non-added elements
    int false_positives = 0;
    for (int i = n; i < n * 2; i++) {
        if (bloom_contains(b, (uint64_t)i)) {
            false_positives++;
        }
    }
    printf("False positives: %d / %d (%.2f%%)\n", false_positives, n, (double)false_positives / n * 100.0);

    bloom_free(&b);
    printf("Bloom Filter test complete.\n\n");
}

void test_tinylfu(int n) {
    printf("Testing TinyLFU with %d elements...\n", n);
    struct tinylfu *tfu = tinylfu_init();
    if (!tfu) {
        printf("Failed to init tinylfu\n");
        return;
    }

    // Access pattern:
    // 0: 1 time
    // 1: 2 times
    // ...
    // 9: 10 times
    int num_items = 10;
    if (n < num_items) num_items = n;

    for (int i = 0; i < num_items; i++) {
        for (int j = 0; j <= i; j++) {
            tinylfu_access(tfu, (uint64_t)i);
        }
    }

    // Check estimates
    printf("Checking estimates (Item: Actual vs Estimate):\n");
    for (int i = 0; i < num_items; i++) {
        uint64_t est = tinylfu_estimate(tfu, (uint64_t)i);
        printf("  %d: %d vs %" PRIu64 "\n", i, i + 1, est);
        // Estimate should be at least the actual count (TinyLFU is approximate, but usually close or slightly higher due to collisions)
        // However, TinyLFU resets, so it might be lower if reset happened.
        // But with small N and large filters, it should be accurate.
        // Let's just print for manual verification in this simple test.
    }

    // Test admit
    // 0 has count 1, 9 has count 10.
    // 9 should be admitted over 0.
    if (tinylfu_admit(tfu, (uint64_t)9, (uint64_t)0)) {
         printf("PASS: TinyLFU admits 9 (freq 10) over 0 (freq 1)\n");
    } else {
         printf("FAIL: TinyLFU did NOT admit 9 (freq 10) over 0 (freq 1)\n");
    }

    // 0 should NOT be admitted over 9
    if (!tinylfu_admit(tfu, (uint64_t)0, (uint64_t)9)) {
         printf("PASS: TinyLFU rejects 0 (freq 1) over 9 (freq 10)\n");
    } else {
         printf("FAIL: TinyLFU admitted 0 (freq 1) over 9 (freq 10)\n");
    }

    tinylfu_free(&tfu);
    printf("TinyLFU test complete.\n\n");
}

void test_counting_bloom(int n) {
    printf("Testing Counting Bloom Filter with %d elements...\n", n);
    // Use enough counters to avoid too many collisions for this test
    struct counting_bloom *cb = counting_bloom_init(n * 10); 
    if (!cb) {
        printf("Failed to init counting bloom filter\n");
        return;
    }

    // Add elements with varying frequencies
    // 0: 1 time
    // ...
    // 15: 16 times (should saturate at 15 if 4 bits)
    int max_count = 20;
    
    for (int i = 0; i < max_count; i++) {
        for (int j = 0; j <= i; j++) {
            counting_bloom_add(cb, (uint64_t)i);
        }
    }

    printf("Checking Counting Bloom Filter estimates:\n");
    for (int i = 0; i < max_count; i++) {
        uint64_t est = counting_bloom_estimate(cb, (uint64_t)i);
        uint64_t expected = i + 1;
        if (expected > 15) expected = 15; // Saturation at 4 bits (0-15)
        
        printf("  %d: Actual %d, Estimate %" PRIu64 "\n", i, i + 1, est);
        
        if (est != expected) {
             printf("FAIL: Estimate mismatch for %d. Expected %" PRIu64 ", got %" PRIu64 "\n", i, expected, est);
        }
    }

    counting_bloom_free(&cb);
    printf("Counting Bloom Filter test complete.\n\n");
}

int main(void) {
    test_bloom(1000);
    test_counting_bloom(100);
    test_tinylfu(100);
    return 0;
}
