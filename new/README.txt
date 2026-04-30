================================================================================
                    binfuse filter64 -- 64-bit Binary Fuse Filter
================================================================================

1. 简介
--------

filter64 是在 binfuse 库基础上扩展的 64 位指纹 Binary Fuse Filter。

Binary Fuse Filter 是一种概率型数据结构，用于快速判断一个元素是否在集合中：
  - 如果元素在集合中，contains() 一定返回 true（零漏判）
  - 如果元素不在集合中，contains() 有极小概率误判为 true

不同指纹位宽对应的误判率：
  filter8   -- 1/2^8   = 1/256        (0.39%)
  filter16  -- 1/2^16  = 1/65536      (0.0015%)
  filter64  -- 1/2^64  = 1/1.8x10^19  (约等于零)

filter64 的误判率为 1/2^64，在实际应用中可视为精确匹配。


2. 依赖与环境
--------------

编译器要求：支持 C++20 的编译器
  - GCC >= 10.2
  - Clang >= 18.1
  - MSVC (MinGW)

构建工具：CMake >= 3.16

库位置：prelib/binfuse/


3. 项目集成
------------

在你的 CMakeLists.txt 中添加：

    cmake_minimum_required(VERSION 3.16)
    project(my_project)

    add_subdirectory(prelib/binfuse)

    add_executable(my_exe main.cpp)
    target_link_libraries(my_exe PRIVATE binfuse)

头文件引用：

    #include "binfuse/filter.hpp"          // filter64, filter64_sink, filter64_source
    #include "binfuse/sharded_filter.hpp"  // sharded_filter64_sink, sharded_filter64_source


4. 构建与测试
--------------

    cd <repository-root>/new/
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build

构建完成后测试会自动运行。如需单独运行测试：

    cd build && ctest --output-on-failure


5. 使用方法
------------

5.1 内存中使用（最简单）

    #include "binfuse/filter.hpp"
    #include <vector>
    #include <cstdint>

    int main() {
        // 用一组 uint64_t 构建过滤器
        binfuse::filter64 filter(std::vector<std::uint64_t>{
            0x0000000000000001,
            0x0000000000000002,
            0x0000000000000003,
        });

        // 查询
        if (filter.contains(0x0000000000000001)) {
            // 命中：元素在集合中
        }

        if (!filter.contains(0x9999999999999999)) {
            // 未命中：元素一定不在集合中
        }

        return 0;
    }

5.2 保存到磁盘 / 从磁盘加载（通过 mmap 高效查询）

    #include "binfuse/filter.hpp"

    int main() {
        // 构建并保存
        binfuse::filter64_sink sink(std::vector<std::uint64_t>{
            0x0000000000000001,
            0x0000000000000002,
            0x0000000000000003,
        });
        sink.save("my_filter64.bin");

        // 加载并查询
        binfuse::filter64_source source;
        source.load("my_filter64.bin");

        source.contains(0x0000000000000001);  // true
        source.contains(0xFFFFFFFFFFFFFFFF);  // 几乎不可能误判

        return 0;
    }

5.3 分片过滤器（适合大数据集，控制内存占用）

    #include "binfuse/sharded_filter.hpp"

    int main() {
        // 写入：shard_bits=4 表示 2^4=16 个分片
        binfuse::sharded_filter64_sink sink("sharded64.bin", 4);
        sink.stream_prepare();

        // 数据必须按升序添加
        sink.stream_add(0x0000000000000001);
        sink.stream_add(0x0000000000000002);
        sink.stream_add(0x0000000000000003);
        // ... 继续按顺序添加更多数据
        sink.stream_finalize();

        // 读取并查询
        binfuse::sharded_filter64_source source("sharded64.bin", 4);
        source.contains(0x0000000000000001);  // true

        return 0;
    }

5.4 手动逐分片构建

    #include "binfuse/sharded_filter.hpp"

    int main() {
        // shard_bits=1 表示 2 个分片（按最高位分）
        binfuse::sharded_filter64_sink sink("sharded64.bin", 1);

        // 分片 0：最高位为 0 的数据
        binfuse::filter64 low_shard(std::vector<std::uint64_t>{
            0x0000000000000001,
            0x0000000000000002,
        });
        sink.add_shard(low_shard, 0);

        // 分片 1：最高位为 1 的数据
        binfuse::filter64 high_shard(std::vector<std::uint64_t>{
            0x8000000000000001,
            0x8000000000000002,
        });
        sink.add_shard(high_shard, 1);

        // 查询
        binfuse::sharded_filter64_source source("sharded64.bin", 1);
        source.contains(0x0000000000000001);  // true
        source.contains(0x8000000000000001);  // true

        return 0;
    }


6. 类型别名速查
-----------------

    类型名                        说明
    ----------------------------  ------------------------------------
    binfuse::filter64             内存中的 64 位过滤器
    binfuse::filter64_sink        可持久化过滤器（写入/保存）
    binfuse::filter64_source      可持久化过滤器（读取/加载，mmap）
    binfuse::sharded_filter64_sink    分片过滤器（写入）
    binfuse::sharded_filter64_source  分片过滤器（读取）


7. 存储开销
------------

filter64 每个元素约占 9 字节（8 字节指纹 + 结构开销）。

    元素数量        filter8 大小    filter64 大小
    ----------      ------------    -------------
    100 万          ~1.1 MB         ~9 MB
    1 亿            ~113 MB         ~900 MB
    10 亿           ~1.1 GB         ~9 GB

分片过滤器可以将构建时的内存峰值控制在单个分片大小以内。


8. 注意事项
------------

- filter64 构建后不可修改（immutable），所有数据必须一次性提供
- 输入数据类型为 uint64_t，如需存储字符串等数据，请先哈希为 uint64_t
- stream_add() 要求数据严格按升序输入，否则会抛出异常
- 文件格式为本机字节序（native endianness），不同架构间不可直接移植
- 分片过滤器的 shard_bits 在写入和读取时必须一致


9. 修改的文件清单
------------------

本次扩展修改了以下文件：

  prelib/binfuse/ext/xor_singleheader/include/binaryfusefilter.h
    -- 添加 binary_fuse64_t 结构体及全部 C API 函数

  prelib/binfuse/include/binfuse/filter.hpp
    -- 更新 filter_type concept，添加 ftype<binary_fuse64_t> 特化和类型别名

  prelib/binfuse/include/binfuse/sharded_filter.hpp
    -- 添加 sharded_filter64 类型别名

  prelib/binfuse/test/filter.cpp
    -- 添加 save_load64, large64, large64_persistent 测试

  prelib/binfuse/test/sharded_filter.cpp
    -- 添加 large64, large64_32 测试

所有 30 项测试均已通过。
