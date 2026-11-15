# 有状态流过滤功能 — 实现与测试报告

日期：2026-11-16

## 功能概述

为 tcpdump 增加有状态流过滤（默认行为不变，仍为无状态 BPF）。按 5 元组
（IPv4/IPv6 双方向归一为同一流）维护有界流表，新增命令行选项：

| 选项 | 说明 |
|---|---|
| `--flow-first N` | 每个流只放行前 N 个包（N=1 即首包） |
| `--flow-regex PATTERN` | 只放行载荷匹配 POSIX ERE 的流；匹配前的包按上界缓冲，命中后补发，可抓到完整会话 |
| `--flow-dir fwd\|rev\|both` | 按流方向过滤（方向以首包发送方为发起方） |
| `--flow-max N` | 流表容量（默认 65536），表满时 LRU 逐出 |
| `--flow-timeout SEC` | 流空闲超时（默认 300s），按包时间戳摊还扫描 |
| `--flow-bufmax BYTES` | 每流载荷扫描缓冲上界（默认 16384） |
| `--flow-prebuf BYTES` | 每流匹配前包缓冲上界（默认 65536） |
| `--flow-maxmem BYTES` | 全局缓冲内存上界（默认 64MiB） |
| `--flow-stats` | 退出时向 stderr 输出统计指标 |
| `--flow-audit` | 向 stderr 输出流生命周期审计事件 |

设计要点：

- **失败回退（fail-open）**：无法分类（不支持的链路类型、截断包、未知流
  的非首分片）或资源耗尽（全局内存上限）时，按无状态 BPF 的结果放行，
  不漏包，并计入 fallback 统计。
- **分片**：首分片注册到有界分片映射表（(地址, 协议, IP ID) → 流，4096 项
  LRU），后续分片归属同一流，载荷按到达序进入正则扫描缓冲，可跨分片匹配。
- **乱序**：流表不依赖序号，乱序不破坏状态；正则按到达序字节流匹配
  （文档已说明此限制）。
- **内存有界**：流表项数、每流扫描缓冲、每流匹配前包缓冲、全局内存均有
  硬上界，无每包无界分配。
- **并发**：所有公开入口在有 pthread 时通过互斥锁串行化，`lock_waits`
  指标计数；tcpdump 当前回调为单线程，锁为零竞争开销。
- **pcap 输出格式不变**：过滤器只选择哪些包被写出/打印。

## 改动文件

修改：
- `tcpdump.c` — 新增 `--flow-*` 选项解析、三个抓包回调（print/dump/
  dump_and_trunc）中的过滤钩子、缓冲包补发回调、退出时统计输出、usage
- `CMakeLists.txt` — 加入 flowfilter.c；检查 regex.h/regcomp；查找 Threads
- `Makefile.in` — CSRC/HDR 加入 flowfilter.c/h
- `configure.ac` — 检查 regex.h、pthread.h、regcomp、pthread_mutex_lock
- `cmakeconfig.h.in` — HAVE_REGEX_H / HAVE_REGCOMP / HAVE_PTHREAD_H
- `tcpdump.1.in` — 选项文档与 FLOW FILTER 章节
- `tests/TESTLIST` — 8 个新测试

新增：
- `flowfilter.h`、`flowfilter.c` — 流过滤模块（约 1100 行）
- `testprogs/make-flow-test-pcaps.py` — 测试 pcap 生成器
- `tests/flow-{basic,regex,frag,full}.pcap` — 测试输入
- `tests/flow-{first1,first3,dir-fwd,dir-rev,regex,regex-dir,frag,full}.out` —
  期望输出

## 构建与测试命令

环境无系统 libpcap，本地构建依赖：

```
# libpcap 1.10.5（源码目录独立，构建目录分离）
cmake -S /home/gyr/build-deps/libpcap-src/libpcap-1.10.5 \
      -B /home/gyr/build-deps/libpcap-build \
      -DCMAKE_INSTALL_PREFIX=/home/gyr/build-deps/install \
      -DBUILD_SHARED_LIBS=OFF -DENABLE_REMOTE=OFF
cmake --build /home/gyr/build-deps/libpcap-build -j && cmake --install /home/gyr/build-deps/libpcap-build

# tcpdump
cmake -S /home/gyr/feedback/uid21999 -B /home/gyr/feedback/uid21999/build \
      -DPCAP_ROOT=/home/gyr/build-deps/install
cmake --build /home/gyr/feedback/uid21999/build -j
```

测试：

```
# 完整测试套件（含 8 个新流过滤测试）
cd build && TCPDUMP_BIN=./tcpdump CONFIG_H=./config.h perl ../testprogs/TESTrun

# 单独运行新测试
TCPDUMP_BIN=./tcpdump CONFIG_H=./config.h perl ../testprogs/TESTrun --one flow-first1
  （flow-first1 flow-first3 flow-dir-fwd flow-dir-rev flow-regex
    flow-regex-dir flow-frag flow-full）

# ASan/UBSan + 泄漏检测构建
cmake -S . -B /tmp/build-asan -DPCAP_ROOT=/home/gyr/build-deps/install \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"

# autotools 配置语法检查
autoconf -o /tmp/configure-test configure.ac
```

## 测试结果

- 完整套件：**800 passed, 0 failed, 13 skipped**（含全部 8 个新流过滤测试，
  基线 792 + 8）。
- ASan/UBSan + LeakSanitizer：首包/前 N/方向/载荷/分片/表满/内存上限
  各场景全部干净，无泄漏（`flow_filter_cleanup` 释放全部状态）。
- `autoconf` 语法检查通过（仅有既有的 AC_PROG_CC_C99 过时警告）。
- man 页 `man --warnings` 检查 0 警告。
- 默认无状态行为不变：不加 `--flow-*` 时输出与基线逐字节一致；
  `-w` 输出仍为标准 pcap（用 tcpdump 回读验证）。

## 覆盖的场景

| 场景 | 测试 | 结果 |
|---|---|---|
| 首包 | flow-first1（3 流交错，只出每流首包） | 通过 |
| 前 N 包 | flow-first3（每流前 3 包，含双向） | 通过 |
| 流方向 | flow-dir-fwd / flow-dir-rev | 通过 |
| 载荷正则 | flow-regex（命中流完整会话，未命中流全抑制）、flow-regex-dir（方向组合） | 通过 |
| 分片 | flow-frag（跨分片正则命中；孤儿分片 fail-open 放行） | 通过 |
| 表满 | flow-full（--flow-max 4，6 流 → 12 次表满/逐出，确定性输出） | 通过 |
| 流超时 | 手工构造 5s 间隔 pcap：超时后重建流，首包再次放行 | 通过 |
| 回退 | 不支持的 DLT（IEEE802_15_4）→ 警告并转无状态；--flow-maxmem 1024 → fail-open | 通过 |

## 审计与统计指标样例

`--flow-audit`（流生命周期事件）：

```
flowfilter: create ipv4 192.168.1.10:40000 <-> 192.168.1.20:8080
flowfilter: create ipv4 192.168.1.11:50000 <-> 192.168.1.20:443
flowfilter: regex match ipv4 192.168.1.10:40000 <-> 192.168.1.20:8080
```

`--flow-stats`（正则会话抓取，flow-regex.pcap）：

```
flow filter statistics:
  packets: 10 presented, 3 passed, 7 suppressed
  flows: 2 created, 2 active, 8 flow hits
  table: 0 full events, 0 evictions, 0 timeouts
  fragments: 0 hits, 0 misses
  regex: 1 matches, 0 pre-match packets dropped (buffer cap)
  fallback: 0 fail-open events (packets passed as stateless)
  memory: 695 bytes current, 1065 bytes peak, 0 memory-cap events
  concurrency: 10 lock acquisitions
```

表满场景（flow-full.pcap, --flow-max 4）：`table: 12 full events,
12 evictions`；分片场景（flow-frag.pcap）：`fragments: 2 hits, 1 misses`，
`fallback: 1`（孤儿分片放行）；内存上限场景（--flow-maxmem 1024）：
`memory: 951 bytes current, 964 bytes peak, 1 memory-cap events`，
`fallback: 1`；超时场景：`table: ... 1 timeouts`。

## 已知限制

- 正则匹配基于到达序字节流，不做 TCP 序号重组（乱序段的匹配可能漏报，
  但不会误丢其他包）。
- 链路类型支持 Ethernet（含 VLAN）、Linux SLL/SLL2、RAW IP、NULL/LOOP；
  其他类型自动回退无状态过滤并告警。
- 实时抓包退出时统计随 `info()` 输出；离线 `-r` 需 `--flow-stats` 显式开启
  （保持测试框架对 stderr 洁净的要求）。
