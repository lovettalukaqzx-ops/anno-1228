#include "binfuse/additive_filter.hpp"
#include "binaryfusefilter.h"
#include "gtest/gtest.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {
constexpr std::uint64_t kMask40 = binfuse::additive_filter40::kDefaultModulus - 1;
}

TEST(additive_filter40, default_construct) { // NOLINT
  binfuse::additive_filter40 filter;
  EXPECT_FALSE(filter.is_populated());
}

TEST(additive_filter40, populate_and_decode) { // NOLINT
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

  binfuse::additive_filter40 filter(keys, values);

  EXPECT_TRUE(filter.is_populated());
  EXPECT_EQ(filter.size(), keys.size());
  EXPECT_GT(filter.array_length(), 0U);
  ASSERT_NE(filter.data(), nullptr);

  bool any_non_zero_slot = false;
  for (std::size_t i = 0; i < filter.array_length(); ++i) {
    EXPECT_EQ(filter.data()[i] & ~kMask40, 0ULL);
    any_non_zero_slot = any_non_zero_slot || (filter.data()[i] != 0ULL);
  }
  EXPECT_TRUE(any_non_zero_slot);

  for (std::size_t i = 0; i < keys.size(); ++i) {
    EXPECT_EQ(filter.decode(keys[i]), values[i] & kMask40);
  }
  EXPECT_TRUE(filter.verify(keys, values));
}

TEST(additive_filter40, positions_match_binary_fuse_geometry) { // NOLINT
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

  binfuse::additive_filter40 filter(keys, values, seed, binfuse::additive_filter40::kDefaultModulus);

  binary_fuse64_t expected{};
  ASSERT_TRUE(binary_fuse64_allocate(static_cast<std::uint32_t>(keys.size()), &expected));
  expected.Seed = seed;

  EXPECT_EQ(filter.seed(), seed);
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

TEST(additive_filter40, masks_values_to_40_bits) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x10ULL,
      0x20ULL,
      0x30ULL,
      0x40ULL,
  };
  const std::vector<std::uint64_t> values{
      (1ULL << 45) | 0x12345ULL,
      (1ULL << 50) | 0xABCDEULL,
      (1ULL << 60) | 0x54321ULL,
      ~0ULL,
  };

  binfuse::additive_filter40 filter(keys, values);

  for (std::size_t i = 0; i < keys.size(); ++i) {
    EXPECT_EQ(filter.decode(keys[i]), values[i] & kMask40);
  }
}

TEST(additive_filter40, duplicate_keys_with_same_value_are_accepted) { // NOLINT
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

  binfuse::additive_filter40 filter(keys, values);

  EXPECT_EQ(filter.size(), 3U);
  EXPECT_EQ(filter.decode(0x11ULL), 0x123ULL);
  EXPECT_EQ(filter.decode(0x22ULL), 0x456ULL);
  EXPECT_EQ(filter.decode(0x33ULL), 0x789ULL);
}

TEST(additive_filter40, duplicate_keys_with_different_values_throw) { // NOLINT
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

  EXPECT_THROW((void)binfuse::additive_filter40(keys, values), std::invalid_argument);
}

TEST(additive_filter40, deterministic_seed_gives_same_layout) { // NOLINT
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

  binfuse::additive_filter40 filter_a(keys, values, seed, binfuse::additive_filter40::kDefaultModulus);
  binfuse::additive_filter40 filter_b(keys, values, seed, binfuse::additive_filter40::kDefaultModulus);

  EXPECT_EQ(filter_a.seed(), seed);
  EXPECT_EQ(filter_b.seed(), seed);
  EXPECT_EQ(filter_a.array_length(), filter_b.array_length());
  for (std::size_t i = 0; i < filter_a.array_length(); ++i) {
    EXPECT_EQ(filter_a.data()[i], filter_b.data()[i]);
  }
}
