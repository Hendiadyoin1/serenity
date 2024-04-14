/*
 * Copyright (c) 2020, Ali Mohammad Pur <mpfard@serenityos.org>
 * Copyright (c) 2023, Jelle Raaijmakers <jelle@gmta.nl>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Endian.h>
#include <AK/Memory.h>
#include <AK/Platform.h>
#include <AK/Types.h>
#include <LibCrypto/Hash/SHA1.h>

#if (ARCH(I386) || ARCH(X86_64)) && defined __GNUC__ && __GNUC__ >= 11
#    include <emmintrin.h> // SSE2 _mm_add_epi32 _mm_loadu_si128 _mm_set_epi32 _mm_set_epi64x _mm_setzero_si128 _mm_shuffle_epi32 _mm_storeu_si128 _mm_xor_si128
#    include <immintrin.h> // SHA _mm_sha1msg1_epu32 _mm_sha1msg2_epu32 _mm_sha1nexte_epu32 _mm_sha1rnds4_epu32
#    include <smmintrin.h> // SSE4.1 _mm_extract_epi32
#    include <tmmintrin.h> // SSSE3 _mm_shuffle_epi8
#    define SHA1_ATTRIBUTE_TARGET_DEFAULT __attribute__((target("default")))
#    define SHA1_ATTRIBUTE_TARGET_X86 __attribute__((target("sse2,ssse3,sse4.1,sha")))
#else
#    define SHA1_ATTRIBUTE_TARGET_DEFAULT
#endif

namespace Crypto::Hash {

static constexpr auto ROTATE_LEFT(u32 value, size_t bits)
{
    return (value << bits) | (value >> (32 - bits));
}

SHA1_ATTRIBUTE_TARGET_DEFAULT static void transform_impl(u32 (&state)[5], u8 const (&data)[64])
{
    constexpr static auto Rounds = 80;

    u32 blocks[80];
    for (size_t i = 0; i < 16; ++i)
        blocks[i] = AK::convert_between_host_and_network_endian(((u32 const*)data)[i]);

    // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
    for (size_t i = 16; i < Rounds; ++i)
        blocks[i] = ROTATE_LEFT(blocks[i - 3] ^ blocks[i - 8] ^ blocks[i - 14] ^ blocks[i - 16], 1);

    auto a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    u32 f, k;

    for (size_t i = 0; i < Rounds; ++i) {
        if (i <= 19) {
            f = (b & c) | ((~b) & d);
            k = SHA1Constants::RoundConstants[0];
        } else if (i <= 39) {
            f = b ^ c ^ d;
            k = SHA1Constants::RoundConstants[1];
        } else if (i <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1Constants::RoundConstants[2];
        } else {
            f = b ^ c ^ d;
            k = SHA1Constants::RoundConstants[3];
        }
        auto temp = ROTATE_LEFT(a, 5) + f + e + k + blocks[i];
        e = d;
        d = c;
        c = ROTATE_LEFT(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    // "security" measures, as if SHA1 is secure
    a = 0;
    b = 0;
    c = 0;
    d = 0;
    e = 0;
    secure_zero(blocks, 16 * sizeof(u32));
}

#if (ARCH(I386) || ARCH(X86_64)) && defined __GNUC__ && __GNUC__ >= 11
SHA1_ATTRIBUTE_TARGET_X86 static void transform_impl(u32 (&state)[5], u8 const (&data)[64])
{
    // Set up constant for reversing input buffer.
    __m128i reverse_8 = _mm_set_epi64x(0x0001020304050607ull, 0x08090a0b0c0d0e0full);
    // Load state into working registers.
    __m128i abcd_1 = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&state[0]));
    abcd_1 = _mm_shuffle_epi32(abcd_1, 0x1b);
    __m128i e = _mm_set_epi32(*reinterpret_cast<int const*>(&state[4]), 0, 0, 0);
    // Here could start `for' or `while' loop in case we processed more than one block at once.
    // Save old state.
    __m128i old_abcd = abcd_1;
    __m128i old_e = e;
    // Load four 32bit integers into working registers.
    __m128i msg_0 = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&data[0 * 16]));
    msg_0 = _mm_shuffle_epi8(msg_0, reverse_8);
    // Four rounds (0-3) of the SHA-1 algorithm.
    e = _mm_add_epi32(e, msg_0);
    __m128i abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 0);
    // Load four 32bit integers into working registers.
    __m128i msg_1 = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&data[1 * 16]));
    msg_1 = _mm_shuffle_epi8(msg_1, reverse_8);
    // Four rounds (4-7) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_1);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 0);
    // Load four 32bit integers into working registers.
    __m128i msg_2 = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&data[2 * 16]));
    msg_2 = _mm_shuffle_epi8(msg_2, reverse_8);
    // Four rounds (8-11) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_2);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 0);
    // Load four 32bit integers into working registers.
    __m128i msg_3 = _mm_loadu_si128(reinterpret_cast<__m128i const*>(&data[3 * 16]));
    msg_3 = _mm_shuffle_epi8(msg_3, reverse_8);
    // Four rounds (12-15) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_3);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 0);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    // Four rounds (16-19) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_0);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 0);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    // Four rounds (20-23) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_1);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 1);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    // Four rounds (24-27) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_2);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 1);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    // Four rounds (28-31) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_3);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 1);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    // Four rounds (32-35) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_0);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 1);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    // Four rounds (36-39) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_1);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 1);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    // Four rounds (40-43) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_2);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 2);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    // Four rounds (44-47) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_3);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 2);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    // Four rounds (48-51) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_0);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 2);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    // Four rounds (52-55) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_1);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 2);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    // Four rounds (56-59) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_2);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 2);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    // Four rounds (60-63) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_3);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 3);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    // Four rounds (64-67) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_0);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 3);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    // Four rounds (68-71) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_1);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 3);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    // Four rounds (72-77) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_2, msg_2);
    abcd_2 = _mm_sha1rnds4_epu32(abcd_1, e, 3);
    // Generate next input, aka preprocessing, described in NIST FIPS PUB 180-4 section 6.1.2.1.
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    // Four rounds (76-79) of the SHA-1 algorithm.
    e = _mm_sha1nexte_epu32(abcd_1, msg_3);
    abcd_1 = _mm_sha1rnds4_epu32(abcd_2, e, 3);
    // Finish computation of the last `e' value.
    msg_0 = _mm_setzero_si128();
    e = _mm_sha1nexte_epu32(abcd_2, msg_0);
    // Sum current working registers with saved state from before.
    abcd_1 = _mm_add_epi32(abcd_1, old_abcd);
    e = _mm_add_epi32(e, old_e);
    // Here could end `for' or `while' loop in case we processed more than one block at once.
    // Save working registers into state.
    abcd_1 = _mm_shuffle_epi32(abcd_1, 0x1b);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), abcd_1);
    state[4] = static_cast<u32>(_mm_extract_epi32(e, 3));
}
#endif

inline void SHA1::transform(u8 const (&data)[BlockSize])
{
    transform_impl(m_state, data);
}

void SHA1::update(u8 const* message, size_t length)
{
    while (length > 0) {
        size_t copy_bytes = AK::min(length, BlockSize - m_data_length);
        __builtin_memcpy(m_data_buffer + m_data_length, message, copy_bytes);
        message += copy_bytes;
        length -= copy_bytes;
        m_data_length += copy_bytes;
        if (m_data_length == BlockSize) {
            transform(m_data_buffer);
            m_bit_length += BlockSize * 8;
            m_data_length = 0;
        }
    }
}

SHA1::DigestType SHA1::digest()
{
    auto digest = peek();
    reset();
    return digest;
}

SHA1::DigestType SHA1::peek()
{
    DigestType digest;
    size_t i = m_data_length;

    // make a local copy of the data as we modify it
    u8 data[BlockSize];
    u32 state[5];
    __builtin_memcpy(data, m_data_buffer, m_data_length);
    __builtin_memcpy(state, m_state, 20);

    if (m_data_length < FinalBlockDataSize) {
        m_data_buffer[i++] = 0x80;
        while (i < FinalBlockDataSize)
            m_data_buffer[i++] = 0x00;

    } else {
        // First, complete a block with some padding.
        m_data_buffer[i++] = 0x80;
        while (i < BlockSize)
            m_data_buffer[i++] = 0x00;
        transform(m_data_buffer);

        // Then start another block with BlockSize - 8 bytes of zeros
        __builtin_memset(m_data_buffer, 0, FinalBlockDataSize);
    }

    // append total message length
    m_bit_length += m_data_length * 8;
    m_data_buffer[BlockSize - 1] = m_bit_length;
    m_data_buffer[BlockSize - 2] = m_bit_length >> 8;
    m_data_buffer[BlockSize - 3] = m_bit_length >> 16;
    m_data_buffer[BlockSize - 4] = m_bit_length >> 24;
    m_data_buffer[BlockSize - 5] = m_bit_length >> 32;
    m_data_buffer[BlockSize - 6] = m_bit_length >> 40;
    m_data_buffer[BlockSize - 7] = m_bit_length >> 48;
    m_data_buffer[BlockSize - 8] = m_bit_length >> 56;

    transform(m_data_buffer);

    for (i = 0; i < 4; ++i) {
        digest.data[i + 0] = (m_state[0] >> (24 - i * 8)) & 0x000000ff;
        digest.data[i + 4] = (m_state[1] >> (24 - i * 8)) & 0x000000ff;
        digest.data[i + 8] = (m_state[2] >> (24 - i * 8)) & 0x000000ff;
        digest.data[i + 12] = (m_state[3] >> (24 - i * 8)) & 0x000000ff;
        digest.data[i + 16] = (m_state[4] >> (24 - i * 8)) & 0x000000ff;
    }
    // restore the data
    __builtin_memcpy(m_data_buffer, data, m_data_length);
    __builtin_memcpy(m_state, state, 20);
    return digest;
}

}
