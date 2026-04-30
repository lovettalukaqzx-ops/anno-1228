#include "binfuse/additive_filter.hpp"
#include "binaryfusefilter.h"
#include "gtest/gtest.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

// ============================================================
//  Tests with default modulus (2^40, backward compatibility)
// ============================================================

TEST(additive_filter, default_construct) { // NOLINT
  binfuse::additive_filter filter;
  EXPECT_FALSE(filter.is_populated());
  EXPECT_EQ(filter.modulus(), binfuse::additive_filter::kDefaultModulus);
}

TEST(additive_filter, populate_and_decode_default_modulus) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x0000000000000000ULL,
      0x0000000000000001ULL,
      0x0000000000000002ULL,
      0x0000000000000003ULL,
      0x0000000000000010ULL,
      0x0000000000000100ULL,
  };
  const std::vector<std::uint64_t> values{
      0x000000000001ULL,
      0x000000123456ULL,
      0x000000ABCDEFULL,
      0x000012345678ULL,
      0x0000FEDCBAULL,
      0x00000F0F0FULL,
  };

  binfuse::additive_filter filter(keys, values);

  EXPECT_TRUE(filter.is_populated());
  EXPECT_EQ(filter.size(), keys.size());
  EXPECT_GT(filter.array_length(), 0U);
  ASSERT_NE(filter.data(), nullptr);

  const auto mod = filter.modulus();
  for (std::size_t i = 0; i < filter.array_length(); ++i) {
    EXPECT_LT(filter.data()[i], mod);
  }

  for (std::size_t i = 0; i < keys.size(); ++i) {
    EXPECT_EQ(filter.decode(keys[i]), values[i] % mod);
  }
  EXPECT_TRUE(filter.verify(keys, values));
}

TEST(additive_filter, positions_match_binary_fuse_geometry) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x0000000000000000ULL,
      0x0000000000000001ULL,
      0x0000000000000002ULL,
      0x0000000000000003ULL,
  };
  const std::vector<std::uint64_t> values{
      1ULL,
      2ULL,
      3ULL,
      4ULL,
  };

  constexpr std::uint64_t seed = 0x50534946696C7472ULL;

  binfuse::additive_filter filter(keys, values, seed,
                                  binfuse::additive_filter::kDefaultModulus);

  binary_fuse64_t expected{};
  ASSERT_TRUE(binary_fuse64_allocate(static_cast<std::uint32_t>(keys.size()), &expected));
  expected.Seed = seed;

  EXPECT_EQ(filter.array_length(), static_cast<std::size_t>(expected.ArrayLength));
  EXPECT_EQ(filter.segment_length(), expected.SegmentLength);
  EXPECT_EQ(filter.segment_length_mask(), expected.SegmentLengthMask);
  EXPECT_EQ(filter.segment_count_length(), expected.SegmentCountLength);

  for (const auto key : keys) {
    const auto positions = filter.positions(key);
    const auto hash      = binary_fuse_mix_split(key, expected.Seed);
    const auto hashes    = binary_fuse64_hash_batch(hash, &expected);

    EXPECT_EQ(positions[0], static_cast<std::size_t>(hashes.h0));
    EXPECT_EQ(positions[1], static_cast<std::size_t>(hashes.h1));
    EXPECT_EQ(positions[2], static_cast<std::size_t>(hashes.h2));
    EXPECT_LT(positions[0], filter.array_length());
    EXPECT_LT(positions[1], filter.array_length());
    EXPECT_LT(positions[2], filter.array_length());
  }

  binary_fuse64_free(&expected);
}

TEST(additive_filter, reduces_values_by_modulus) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x10ULL,
      0x20ULL,
      0x30ULL,
      0x40ULL,
  };
  const auto mod = binfuse::additive_filter::kDefaultModulus;
  const std::vector<std::uint64_t> values{
      (1ULL << 45) | 0x12345ULL,
      (1ULL << 50) | 0xABCDEULL,
      (1ULL << 60) | 0x54321ULL,
      ~0ULL,
  };

  binfuse::additive_filter filter(keys, values);

  for (std::size_t i = 0; i < keys.size(); ++i) {
    EXPECT_EQ(filter.decode(keys[i]), values[i] % mod);
  }
}

TEST(additive_filter, duplicate_keys_with_same_value_are_accepted) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x11ULL,
      0x22ULL,
      0x11ULL,
      0x33ULL,
  };
  const std::vector<std::uint64_t> values{
      0x123ULL,
      0x456ULL,
      0x123ULL,
      0x789ULL,
  };

  binfuse::additive_filter filter(keys, values);

  EXPECT_EQ(filter.size(), 3U);
  EXPECT_EQ(filter.decode(0x11ULL), 0x123ULL);
  EXPECT_EQ(filter.decode(0x22ULL), 0x456ULL);
  EXPECT_EQ(filter.decode(0x33ULL), 0x789ULL);
}

TEST(additive_filter, duplicate_keys_with_different_values_throw) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x11ULL,
      0x22ULL,
      0x11ULL,
  };
  const std::vector<std::uint64_t> values{
      0x123ULL,
      0x456ULL,
      0x999ULL,
  };

  EXPECT_THROW((void)binfuse::additive_filter(keys, values), std::invalid_argument);
}

TEST(additive_filter, deterministic_seed_gives_same_layout) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x101ULL,
      0x202ULL,
      0x303ULL,
      0x404ULL,
      0x505ULL,
  };
  const std::vector<std::uint64_t> values{
      0x11111ULL,
      0x22222ULL,
      0x33333ULL,
      0x44444ULL,
      0x55555ULL,
  };

  constexpr std::uint64_t seed = 0xABCDEF0123456789ULL;

  binfuse::additive_filter filter_a(keys, values, seed,
                                    binfuse::additive_filter::kDefaultModulus);
  binfuse::additive_filter filter_b(keys, values, seed,
                                    binfuse::additive_filter::kDefaultModulus);

  EXPECT_EQ(filter_a.seed(), filter_b.seed());
  EXPECT_EQ(filter_a.array_length(), filter_b.array_length());
  for (std::size_t i = 0; i < filter_a.array_length(); ++i) {
    EXPECT_EQ(filter_a.data()[i], filter_b.data()[i]);
  }
}

// ============================================================
//  Tests with custom prime modulus (simulating BFV batching)
// ============================================================

TEST(additive_filter, custom_prime_modulus) { // NOLINT
  // A 40-bit prime that satisfies t ≡ 1 (mod 8192) for poly_degree=4096
  constexpr std::uint64_t prime_mod = 1099511627777ULL; // 2^40 + 2^13 + 1

  const std::vector<std::uint64_t> keys{
      0xAAAA0001ULL,
      0xAAAA0002ULL,
      0xAAAA0003ULL,
      0xAAAA0004ULL,
      0xAAAA0005ULL,
  };
  const std::vector<std::uint64_t> values{
      100ULL,
      200ULL,
      300ULL,
      prime_mod - 1ULL,  // max value under this modulus
      prime_mod + 50ULL, // should be reduced to 50
  };

  binfuse::additive_filter filter(keys, values, prime_mod);
  EXPECT_EQ(filter.modulus(), prime_mod);

  for (std::size_t i = 0; i < filter.array_length(); ++i) {
    EXPECT_LT(filter.data()[i], prime_mod);
  }

  EXPECT_EQ(filter.decode(keys[0]), 100ULL);
  EXPECT_EQ(filter.decode(keys[1]), 200ULL);
  EXPECT_EQ(filter.decode(keys[2]), 300ULL);
  EXPECT_EQ(filter.decode(keys[3]), prime_mod - 1ULL);
  EXPECT_EQ(filter.decode(keys[4]), 50ULL);
}

TEST(additive_filter, custom_modulus_verify) { // NOLINT
  constexpr std::uint64_t prime_mod = 1099511627777ULL;

  const std::vector<std::uint64_t> keys{
      0xBBBB0001ULL,
      0xBBBB0002ULL,
      0xBBBB0003ULL,
      0xBBBB0004ULL,
  };
  const std::vector<std::uint64_t> values{
      42ULL,
      prime_mod - 42ULL,
      0ULL,
      1ULL,
  };

  binfuse::additive_filter filter(keys, values, prime_mod);
  EXPECT_TRUE(filter.verify(keys, values));
}
