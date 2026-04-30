#pragma once

#include "binaryfusefilter.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace binfuse {

class additive_filter {
public:
  using value_type = std::uint64_t;

  static constexpr value_type kDefaultModulus = UINT64_C(1) << 40;

  additive_filter() = default;

  explicit additive_filter(value_type modulus) : modulus_(modulus) {}

  additive_filter(std::span<const std::uint64_t> keys,
                  std::span<const value_type>    values,
                  value_type                     modulus = kDefaultModulus) : modulus_(modulus) {
    populate(keys, values);
  }

  additive_filter(std::span<const std::uint64_t> keys,
                  std::span<const value_type>    values,
                  std::uint64_t                  seed,
                  value_type                     modulus) : modulus_(modulus) {
    populate(keys, values, seed);
  }

  void populate(std::span<const std::uint64_t> keys, std::span<const value_type> values) {
    populate_impl(keys, values, 0);
  }

  void populate(std::span<const std::uint64_t> keys,
                std::span<const value_type>    values,
                std::uint64_t                  seed) {
    populate_impl(keys, values, seed);
  }

  [[nodiscard]] bool is_populated() const { return size_ > 0; }

  [[nodiscard]] std::size_t size() const { return static_cast<std::size_t>(size_); }

  [[nodiscard]] const value_type* data() const { return slots_.data(); }

  [[nodiscard]] std::size_t array_length() const { return static_cast<std::size_t>(array_length_); }

  [[nodiscard]] std::uint64_t seed() const { return seed_; }

  [[nodiscard]] value_type modulus() const { return modulus_; }

  [[nodiscard]] std::uint32_t segment_length() const { return segment_length_; }

  [[nodiscard]] std::uint32_t segment_length_mask() const { return segment_length_mask_; }

  [[nodiscard]] std::uint32_t segment_count_length() const { return segment_count_length_; }

  [[nodiscard]] std::array<std::size_t, 3> positions(std::uint64_t key) const {
    ensure_populated();

    const auto hash   = binary_fuse_mix_split(key, seed_);
    const auto hashes = hash_batch(hash);
    return {static_cast<std::size_t>(hashes.h0),
            static_cast<std::size_t>(hashes.h1),
            static_cast<std::size_t>(hashes.h2)};
  }

  [[nodiscard]] value_type decode(std::uint64_t key) const {
    ensure_populated();

    const auto pos = positions(key);
    return reduce(slots_[pos[0]] + slots_[pos[1]] + slots_[pos[2]]);
  }

  [[nodiscard]] bool verify(std::span<const std::uint64_t> keys,
                            std::span<const value_type>    values) const {
    if (keys.size() != values.size()) {
      throw std::invalid_argument("keys and values must have the same length");
    }

    for (std::size_t i = 0; i < keys.size(); ++i) {
      if (decode(keys[i]) != reduce(values[i])) {
        return false;
      }
    }
    return true;
  }

private:
  struct entry {
    std::uint64_t key;
    value_type    value;
  };

  [[nodiscard]] value_type reduce(value_type value) const { return value % modulus_; }

  void ensure_populated() const {
    if (!is_populated()) {
      throw std::runtime_error("filter is not populated.");
    }
  }

  static bool entry_less(const entry& lhs, const entry& rhs) { return lhs.key < rhs.key; }

  std::vector<entry> normalize_inputs(std::span<const std::uint64_t> keys,
                                      std::span<const value_type>    values) const {
    if (keys.size() != values.size()) {
      throw std::invalid_argument("keys and values must have the same length");
    }

    std::vector<entry> normalized;
    normalized.reserve(keys.size());
    for (std::size_t i = 0; i < keys.size(); ++i) {
      normalized.push_back(entry{keys[i], reduce(values[i])});
    }

    std::sort(normalized.begin(), normalized.end(), entry_less);

    std::vector<entry> unique_entries;
    unique_entries.reserve(normalized.size());
    for (const auto& current : normalized) {
      if (!unique_entries.empty() && unique_entries.back().key == current.key) {
        if (unique_entries.back().value != current.value) {
          throw std::invalid_argument("duplicate keys must map to the same value under the given modulus");
        }
        continue;
      }
      unique_entries.push_back(current);
    }

    return unique_entries;
  }

  void reset() {
    seed_                 = 0;
    size_                 = 0;
    segment_length_       = 0;
    segment_length_mask_  = 0;
    segment_count_        = 0;
    segment_count_length_ = 0;
    array_length_         = 0;
    slots_.clear();
  }

  void allocate(std::uint32_t size) {
    constexpr std::uint32_t arity = 3;

    size_           = size;
    segment_length_ = size == 0 ? 4 : binary_fuse_calculate_segment_length(arity, size);
    if (segment_length_ > 262144) {
      segment_length_ = 262144;
    }
    segment_length_mask_ = segment_length_ - 1;

    const double size_factor = size <= 1 ? 0.0 : binary_fuse_calculate_size_factor(arity, size);
    const auto capacity =
        size <= 1 ? 0U : static_cast<std::uint32_t>(std::round(static_cast<double>(size) * size_factor));
    const auto init_segment_count =
        (capacity + segment_length_ - 1) / segment_length_ - (arity - 1);

    array_length_ = (init_segment_count + arity - 1) * segment_length_;
    segment_count_ = (array_length_ + segment_length_ - 1) / segment_length_;
    if (segment_count_ <= arity - 1) {
      segment_count_ = 1;
    } else {
      segment_count_ -= (arity - 1);
    }

    array_length_         = (segment_count_ + arity - 1) * segment_length_;
    segment_count_length_ = segment_count_ * segment_length_;
    slots_.assign(array_length_, 0);
  }

  [[nodiscard]] binary_hashes_t hash_batch(std::uint64_t hash) const {
    binary_hashes_t ans;
    const auto hi = binary_fuse_mulhi(hash, segment_count_length_);
    ans.h0        = static_cast<std::uint32_t>(hi);
    ans.h1        = ans.h0 + segment_length_;
    ans.h2        = ans.h1 + segment_length_;
    ans.h1 ^= static_cast<std::uint32_t>(hash >> 18U) & segment_length_mask_;
    ans.h2 ^= static_cast<std::uint32_t>(hash) & segment_length_mask_;
    return ans;
  }

  [[nodiscard]] std::uint32_t hash_index(std::uint64_t index, std::uint64_t hash) const {
    auto h = binary_fuse_mulhi(hash, segment_count_length_);
    h += index * segment_length_;

    const auto hh = hash & ((UINT64_C(1) << 36U) - 1);
    h ^= static_cast<std::size_t>((hh >> (36 - 18 * index)) & segment_length_mask_);
    return static_cast<std::uint32_t>(h);
  }

  void populate_impl(std::span<const std::uint64_t> keys,
                     std::span<const value_type>    values,
                     std::uint64_t                  initial_seed) {
    if (is_populated()) {
      throw std::runtime_error("filter is already populated. You must provide all data at once.");
    }

    auto entries = normalize_inputs(keys, values);
    if (entries.empty()) {
      return;
    }

    allocate(static_cast<std::uint32_t>(entries.size()));
    seed_ = initial_seed;

    std::uint64_t rng_counter;
    if (seed_ != 0) {
      rng_counter = seed_;
    } else {
      rng_counter = UINT64_C(0x726b2b9d438b9d4d);
      seed_       = binary_fuse_rng_splitmix64(&rng_counter);
    }

    std::vector<std::uint64_t> reverse_order(size_ + 1, 0);
    std::vector<std::uint64_t> alone(array_length_, 0);
    std::vector<std::uint8_t>  t2count(array_length_, 0);
    std::vector<std::uint8_t>  reverse_h(size_, 0);
    std::vector<std::uint64_t> t2hash(array_length_, 0);
    std::vector<std::uint32_t> start_pos(1, 0);
    std::vector<value_type>    peeled_values(size_, 0);
    std::array<std::uint32_t, 5> h012{};

    std::uint32_t block_bits = 1;
    while ((UINT32_C(1) << block_bits) < segment_count_) {
      block_bits += 1;
    }
    const auto block = UINT32_C(1) << block_bits;
    start_pos.assign(block, 0);

    std::unordered_map<std::uint64_t, value_type> hash_to_value;
    hash_to_value.reserve(entries.size() * 2);

    for (int loop = 0; true; ++loop) {
      if (loop + 1 > XOR_MAX_ITERATIONS) {
        reset();
        throw std::runtime_error("failed to populate additive_filter");
      }

      std::fill(reverse_order.begin(), reverse_order.end(), 0);
      reverse_order[size_] = 1;
      std::fill(t2count.begin(), t2count.end(), 0);
      std::fill(t2hash.begin(), t2hash.end(), 0);
      std::fill(slots_.begin(), slots_.end(), 0);
      std::fill(start_pos.begin(), start_pos.end(), 0);
      std::fill(reverse_h.begin(), reverse_h.end(), 0);
      std::fill(peeled_values.begin(), peeled_values.end(), 0);
      hash_to_value.clear();

      for (std::uint32_t i = 0; i < block; ++i) {
        start_pos[i] = static_cast<std::uint32_t>((static_cast<std::uint64_t>(i) * size_) >> block_bits);
      }

      const auto mask_block = static_cast<std::uint64_t>(block - 1);
      for (const auto& current : entries) {
        const auto hash = binary_fuse_murmur64(current.key + seed_);
        auto segment_index = hash >> (64 - block_bits);
        while (reverse_order[start_pos[segment_index]] != 0) {
          segment_index = (segment_index + 1) & mask_block;
        }
        reverse_order[start_pos[segment_index]] = hash;
        start_pos[segment_index] += 1;
        hash_to_value.emplace(hash, current.value);
      }

      int error = 0;
      for (std::uint32_t i = 0; i < size_; ++i) {
        const auto hash = reverse_order[i];
        const auto h0   = hash_index(0, hash);
        const auto h1   = hash_index(1, hash);
        const auto h2   = hash_index(2, hash);

        t2count[h0] += 4;
        t2hash[h0] ^= hash;
        t2count[h1] += 4;
        t2count[h1] ^= 1U;
        t2hash[h1] ^= hash;
        t2count[h2] += 4;
        t2count[h2] ^= 2U;
        t2hash[h2] ^= hash;

        error = (t2count[h0] < 4) ? 1 : error;
        error = (t2count[h1] < 4) ? 1 : error;
        error = (t2count[h2] < 4) ? 1 : error;
      }

      if (error != 0) {
        seed_ = binary_fuse_rng_splitmix64(&rng_counter);
        continue;
      }

      std::uint32_t queue_size = 0;
      for (std::uint32_t i = 0; i < array_length_; ++i) {
        alone[queue_size] = i;
        queue_size += ((t2count[i] >> 2U) == 1U) ? 1U : 0U;
      }

      std::uint32_t stack_size = 0;
      while (queue_size > 0) {
        queue_size -= 1;
        const auto index = static_cast<std::uint32_t>(alone[queue_size]);
        if ((t2count[index] >> 2U) == 1U) {
          const auto hash = t2hash[index];

          h012[1] = hash_index(1, hash);
          h012[2] = hash_index(2, hash);
          h012[3] = hash_index(0, hash);
          h012[4] = h012[1];

          const auto found = static_cast<std::uint8_t>(t2count[index] & 3U);
          reverse_h[stack_size]      = found;
          reverse_order[stack_size]  = hash;
          peeled_values[stack_size]  = hash_to_value.at(hash);
          stack_size += 1;

          const auto other_index1 = h012[found + 1];
          alone[queue_size]       = other_index1;
          queue_size += ((t2count[other_index1] >> 2U) == 2U) ? 1U : 0U;
          t2count[other_index1] -= 4;
          t2count[other_index1] ^= binary_fuse_mod3(found + 1);
          t2hash[other_index1] ^= hash;

          const auto other_index2 = h012[found + 2];
          alone[queue_size]       = other_index2;
          queue_size += ((t2count[other_index2] >> 2U) == 2U) ? 1U : 0U;
          t2count[other_index2] -= 4;
          t2count[other_index2] ^= binary_fuse_mod3(found + 2);
          t2hash[other_index2] ^= hash;
        }
      }

      if (stack_size == size_) {
        for (std::uint32_t i = size_ - 1; i < size_; --i) {
          const auto hash  = reverse_order[i];
          const auto found = reverse_h[i];
          h012[0]          = hash_index(0, hash);
          h012[1]          = hash_index(1, hash);
          h012[2]          = hash_index(2, hash);
          h012[3]          = h012[0];
          h012[4]          = h012[1];

          const auto other1 = h012[found + 1];
          const auto other2 = h012[found + 2];
          slots_[h012[found]] =
              reduce(peeled_values[i] + modulus_ - reduce(slots_[other1] + slots_[other2]));
        }
        return;
      }

      seed_ = binary_fuse_rng_splitmix64(&rng_counter);
    }
  }

  value_type            modulus_              = kDefaultModulus;
  std::uint64_t         seed_                 = 0;
  std::uint32_t         size_                 = 0;
  std::uint32_t         segment_length_       = 0;
  std::uint32_t         segment_length_mask_  = 0;
  std::uint32_t         segment_count_        = 0;
  std::uint32_t         segment_count_length_ = 0;
  std::uint32_t         array_length_         = 0;
  std::vector<value_type> slots_;
};

// Backward-compatible alias
using additive_filter40 = additive_filter;

} // namespace binfuse
