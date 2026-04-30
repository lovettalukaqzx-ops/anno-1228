#include "binfuse/filter.hpp"
#include "binaryfusefilter.h"
#include "helpers.hpp"
#include "gtest/gtest.h"
#include <cstdint>
#include <filesystem>
#include <span>
#include <utility>
#include <vector>

TEST(binfuse_filter, default_construct) { // NOLINT
  binfuse::filter8 filter;
  EXPECT_FALSE(filter.is_populated());
}

TEST(binfuse_filter, construct_from_upstream) { // NOLINT
  binary_fuse8_t fil;
  binary_fuse8_allocate(3, &fil);
  std::vector<std::uint64_t> data{
      0x0000000000000000,
      0x0000000000000001,
      0x0000000000000002,
  };
  binary_fuse8_populate(data.data(), static_cast<uint32_t>(data.size()), &fil);

  binfuse::filter8 filter(std::move(fil)); // NOLINT not trivial
  EXPECT_TRUE(filter.is_populated());
  EXPECT_EQ(filter.size(), 3);
  EXPECT_TRUE(filter.contains(0x0000000000000000));
  EXPECT_TRUE(filter.contains(0x0000000000000001));
  EXPECT_TRUE(filter.contains(0x0000000000000002));
}

TEST(binfuse_filter, default_construct_persistent) { // NOLINT
  binfuse::filter8_sink filter_sink;
  EXPECT_FALSE(filter_sink.is_populated());

  binfuse::filter8_source filter_source;
  EXPECT_FALSE(filter_source.is_populated());
}

TEST(binfuse_filter, in_memory) { // NOLINT
  binfuse::filter8 filter(std::vector<std::uint64_t>{
      0x0000000000000000,
      0x0000000000000001, // order is not important
      0x0000000000000002,
  });
  EXPECT_TRUE(filter.is_populated());

  EXPECT_TRUE(filter.contains(0x0000000000000000));
  EXPECT_TRUE(filter.contains(0x0000000000000001));
  EXPECT_TRUE(filter.contains(0x0000000000000002));
}

TEST(binfuse_filter, expose_bins64) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x0000000000000000,
      0x0000000000000001,
      0x0000000000000002,
  };

  binfuse::filter64 filter(keys);

  binary_fuse64_t expected{};
  ASSERT_TRUE(binary_fuse64_allocate(static_cast<std::uint32_t>(keys.size()), &expected));

  EXPECT_EQ(filter.size(), keys.size());
  EXPECT_EQ(filter.array_length(), static_cast<std::size_t>(expected.ArrayLength));
  ASSERT_NE(filter.data(), nullptr);

  bool any_non_zero_bin = false;
  for (std::size_t i = 0; i < filter.array_length(); ++i) {
    any_non_zero_bin = any_non_zero_bin || (filter.data()[i] != 0);
  }
  EXPECT_TRUE(any_non_zero_bin);

  binary_fuse64_free(&expected);
}

TEST(binfuse_filter, positions64) { // NOLINT
  const std::vector<std::uint64_t> keys{
      0x0000000000000000,
      0x0000000000000001,
      0x0000000000000002,
  };

  binfuse::filter64 filter(keys);

  binary_fuse64_t expected{};
  ASSERT_TRUE(binary_fuse64_allocate(static_cast<std::uint32_t>(keys.size()), &expected));

  auto keys_copy = keys;
  ASSERT_TRUE(binary_fuse64_populate(keys_copy.data(), static_cast<std::uint32_t>(keys_copy.size()), &expected));

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

TEST(binfuse_filter, save_load8) { // NOLINT
  {
    binfuse::filter8_sink filter_sink(std::vector<std::uint64_t>{
        0x0000000000000000,
        0x0000000000000001, // order is not important
        0x0000000000000002,
    });
    filter_sink.save("tmp/filter8.bin");

    binfuse::filter8_source filter_source;
    filter_source.load("tmp/filter8.bin");

    EXPECT_TRUE(filter_source.contains(0x0000000000000000));
    EXPECT_TRUE(filter_source.contains(0x0000000000000001));
    EXPECT_TRUE(filter_source.contains(0x0000000000000002));
  }
  std::filesystem::remove("tmp/filter8.bin");
}

TEST(binfuse_filter, save_load16) { // NOLINT
  {
    binfuse::filter16_sink filter_sink(std::vector<std::uint64_t>{
        0x0000000000000000,
        0x0000000000000001, // order is not important
        0x0000000000000002,
    });
    filter_sink.save("tmp/filter16.bin");

    binfuse::filter16_source filter_source;
    filter_source.load("tmp/filter16.bin");

    EXPECT_TRUE(filter_source.contains(0x0000000000000000));
    EXPECT_TRUE(filter_source.contains(0x0000000000000001));
    EXPECT_TRUE(filter_source.contains(0x0000000000000002));
  }
  std::filesystem::remove("tmp/filter16.bin");
}

TEST(binfuse_filter, move) { // NOLINT
  {
    binfuse::filter8_sink filter_sink(std::vector<std::uint64_t>{
        0x0000000000000000,
        0x0000000000000001, // order is not important
        0x0000000000000002,
    });
    filter_sink.save("tmp/filter8.bin");

    binfuse::filter8_source filter_source;
    filter_source.load("tmp/filter8.bin");

    binfuse::filter8_source filter_source2 = std::move(filter_source);

    EXPECT_TRUE(filter_source2.contains(0x0000000000000000));
    EXPECT_TRUE(filter_source2.contains(0x0000000000000001));
    EXPECT_TRUE(filter_source2.contains(0x0000000000000002));
  }
  std::filesystem::remove("tmp/filter8.bin");
}

// larger data tests

TEST(binfuse_filter, large8) { // NOLINT
  auto keys   = load_sample();
  auto filter = binfuse::filter<binary_fuse8_t>(keys);
  EXPECT_TRUE(filter.verify(keys));
  EXPECT_LE(estimate_false_positive_rate(filter), 0.005);
}

TEST(binfuse_filter, large16) { // NOLINT
  auto keys   = load_sample();
  auto filter = binfuse::filter<binary_fuse16_t>(keys);
  EXPECT_TRUE(filter.verify(keys));
  EXPECT_LE(estimate_false_positive_rate(filter), 0.00005);
}

TEST(binfuse_filter, large8_persistent) { // NOLINT
  auto                        keys = load_sample();
  const std::filesystem::path filter_path("tmp/filter.bin");
  {
    auto filter_sink = binfuse::filter8_sink(keys);
    filter_sink.save(filter_path);
    auto filter_source = binfuse::filter8_source();
    filter_source.load(filter_path);
    EXPECT_TRUE(filter_source.verify(keys));
    EXPECT_LE(estimate_false_positive_rate(filter_source), 0.005);
  }
  std::filesystem::remove(filter_path);
}

TEST(binfuse_filter, large16_persistent) { // NOLINT
  auto                        keys = load_sample();
  const std::filesystem::path filter_path("tmp/filter.bin");
  {
    auto filter_sink = binfuse::filter16_sink(keys);
    filter_sink.save(filter_path);
    auto filter_source = binfuse::filter16_source();
    filter_source.load(filter_path);
    EXPECT_TRUE(filter_source.verify(keys));
    EXPECT_LE(estimate_false_positive_rate(filter_source), 0.00005);
  }
  std::filesystem::remove(filter_path);
}

TEST(binfuse_filter, save_load64) { // NOLINT
  {
    binfuse::filter64_sink filter_sink(std::vector<std::uint64_t>{
        0x0000000000000000,
        0x0000000000000001, // order is not important
        0x0000000000000002,
    });
    filter_sink.save("tmp/filter64.bin");

    binfuse::filter64_source filter_source;
    filter_source.load("tmp/filter64.bin");

    EXPECT_TRUE(filter_source.contains(0x0000000000000000));
    EXPECT_TRUE(filter_source.contains(0x0000000000000001));
    EXPECT_TRUE(filter_source.contains(0x0000000000000002));
  }
  std::filesystem::remove("tmp/filter64.bin");
}

TEST(binfuse_filter, large64) { // NOLINT
  auto keys   = load_sample();
  auto filter = binfuse::filter<binary_fuse64_t>(keys);
  EXPECT_TRUE(filter.verify(keys));
  EXPECT_LE(estimate_false_positive_rate(filter), 0.000001);
}

TEST(binfuse_filter, large64_persistent) { // NOLINT
  auto                        keys = load_sample();
  const std::filesystem::path filter_path("tmp/filter64.bin");
  {
    auto filter_sink = binfuse::filter64_sink(keys);
    filter_sink.save(filter_path);
    auto filter_source = binfuse::filter64_source();
    filter_source.load(filter_path);
    EXPECT_TRUE(filter_source.verify(keys));
    EXPECT_LE(estimate_false_positive_rate(filter_source), 0.000001);
  }
  std::filesystem::remove(filter_path);
}
