#include <assert.h>
#include <stdio.h>
#include "algo/sha/sha256-hash.h"

#include "qhash-gate.h"

#define FIXED_FRACTION int8_t
#define FRACTION_BITS 5

static FIXED_FRACTION toFixed(float x)
{
    static_assert(FRACTION_BITS < (sizeof(FIXED_FRACTION) * 8 - 1));
    const FIXED_FRACTION fractionMult = 1 << FRACTION_BITS;
    return (x >= 0.0) ? (x * fractionMult + 0.5f) : (x * fractionMult - 0.5f);
}

#define NIBBLE_MASK (unsigned char)0xF
#define NIBBLE_SIZE 4

static void split_nibbles(const unsigned char input[SHA256_BLOCK_SIZE],
                  unsigned char output[2 * SHA256_BLOCK_SIZE])
{
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; ++i)
    {
        output[2 * i] = (input[i] >> NIBBLE_SIZE) & NIBBLE_MASK;
        output[2 * i + 1] = input[i] & NIBBLE_MASK;
    }
}

void qhash_hash(void *output, const void *input, int length)
{
    unsigned char buf[SHA256_BLOCK_SIZE + NUM_QUBITS * sizeof(FIXED_FRACTION)];
    sha256_full(buf, input, length);

    unsigned char nibbles[2 * SHA256_BLOCK_SIZE];
    split_nibbles(buf, nibbles);

    double expectations[NUM_QUBITS];
    run_simulation(nibbles, expectations);

    for (size_t i = 0; i < NUM_QUBITS; ++i)
    {
        const size_t j = SHA256_BLOCK_SIZE + i * sizeof(FIXED_FRACTION);
        for (size_t k = 0; k < sizeof(FIXED_FRACTION); ++k)
        {
            // Little endian representation
            buf[j + k] = toFixed(expectations[i]) >> (k * 8);
        }
    }
    sha256_full(output, buf, sizeof buf);
}