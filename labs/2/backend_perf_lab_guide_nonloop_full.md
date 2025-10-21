
# 互联网产品开发与运维  
## 主题：后端服务的开销观测与分析 - 实验指导书

---

## 学习产出
- 搭建**最小可观测环境**（`sysstat`/`perf`/`bcc`/`pprof`/FlameGraph）。  
- 按**最佳拓扑**定位 CPU/内存/GC/磁盘 I/O/网络/锁竞争等瓶颈。  
- 用**数据与图形证据**（RPS、分位延迟、火焰图/pprof）撰写因果链。  
- 完成**一次优化与复测**并量化对比。

---

## 实验前提与评分
- OS：Linux（x86_64，内核 ≥ 5.4，需 `sudo`）
- Go 基础（示例服务为 Go）

---

## 快速约定（请先设置）

```bash
# 1) 选择一个【非回环】地址作为对外访问地址（可为内网或公网）
#    推荐优先取默认路由网卡的 IPv4 地址：
export SERVER_ADDR=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
#    若命令不可用，也可用： export SERVER_ADDR=$(hostname -I | awk '{print $1}')

# 2) 端口（示例服务默认 :8080）
export SERVER_PORT=8080

# 3) 安全防护提示：确保本机防火墙/云安全组放通 $SERVER_PORT/tcp
```

> 说明：
> 1) **不要**使用 `127.0.0.1`；在“单机模式”即便使用本机的内网地址，连接仍可能经内核的本地路径，**不会产生真实 NIC/IRQ 成本**——这属于单机模式的已知局限，但不影响 CPU/GC/锁/本机 I/O 等实验。
> 2) 文中所有的观测脚本中的几乎每一行命令都需要在独立的终端中运行（部分是两三行命令观测一个指标），注意识别命令观测的指标，观测不同指标的命令需要分工完成，不要直接复制在一个终端运行全部命令

---

## 环境配置（Debian/Ubuntu 示例）
```bash
sudo apt update
sudo apt install -y build-essential git curl wget make \
  linux-tools-common linux-tools-$(uname -r) linux-headers-$(uname -r) \
  sysstat bpfcc-tools bpftrace strace perf-tools-unstable gdb \
  golang-go wrk jq gnuplot graphviz

# FlameGraph
# 如果使用了zsh，请把.bashrc替换为.zshrc
git clone https://github.com/brendangregg/FlameGraph ~/FlameGraph
echo 'export PATH=$HOME/FlameGraph:$PATH' >> ~/.bashrc && source ~/.bashrc
```

---

## 三种实验模式与选型

| 模式 | 适用目标 | 优点 | 局限 | 本指导书绑定场景 |
|---|---|---|---|---|
| **单机**（服务与压测同一台） | 应用内部热点：CPU/GC/锁/syscall，本机磁盘 I/O | 成本低、复现快 | 本机路径不含真实 NIC；进程争用 CPU/LLC | `/cpu`、`/io`、`/alloc`、syscall/锁、**系统基线** |
| **网络隔离**（namespace+veth+tc） | 演示时延/带宽/丢包对 RPS/尾延迟影响 | 无需第二台；可注入网络条件 | 无真实 NIC/IRQ；需 NAT | **仅无第二台机器时**替代网络实验，这种模式可以先不考虑，如有更多时间可以尝试 |
| **多机**（负载机 ↔ 服务机） | 端到端容量、网络/NIC/IRQ/队列调优 | 最接近生产 | 需要第二台主机 | 轻载连通性、网络容量与 SLA 对照 |

> 访问统一使用 `http://$SERVER_ADDR:$SERVER_PORT/...`（**$SERVER_ADDR 不能是 127.0.0.1**）。

---

## 示例后端服务（Go，含可控瓶颈与 pprof）

**main.go（可直接编译运行）**
```go
package main

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	pp "net/http/pprof"
)

func fib(n int) int {
	if n < 2 {
		return n
	}
	return fib(n-1) + fib(n-2) // 故意用指数级递归 -> CPU瓶颈
}

func cpuHandler(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n == 0 {
		n = 42
	}
	x := fib(n)
	fmt.Fprintf(w, "fib(%d)=%d\n", n, x)
}

func ioHandler(w http.ResponseWriter, r *http.Request) {
	// 模拟大块写入 + fsync -> 触发磁盘I/O瓶颈
	bsKB, _ := strconv.Atoi(r.URL.Query().Get("bs_kb"))
	if bsKB == 0 {
		bsKB = 1024
	}
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count == 0 {
		count = 128
	}
	fn := "/tmp/io_test.bin"
	f, err := os.Create(fn)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer f.Close()
	buf := make([]byte, bsKB*1024)
	for i := 0; i < count; i++ {
		_, _ = crand.Read(buf)
		if _, err := f.Write(buf); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	f.Sync()
	fmt.Fprintf(w, "wrote %d x %dKB\n", count, bsKB)
}

func allocHandler(w http.ResponseWriter, r *http.Request) {
	// 模拟大量短期分配 -> GC压力 & 内存抖动
	kb, _ := strconv.Atoi(r.URL.Query().Get("kb"))
	if kb == 0 {
		kb = 25600 // 25MB
	}
	b := make([]byte, kb*1024)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	time.Sleep(50 * time.Millisecond)
	runtime.KeepAlive(b)
	io.WriteString(w, "alloc done\n")
}

func root(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "OK\n")
}

func main() {
	mux := http.NewServeMux()
	// 业务路由
	mux.HandleFunc("/", root)
	mux.HandleFunc("/cpu", cpuHandler)
	mux.HandleFunc("/io", ioHandler)
	mux.HandleFunc("/alloc", allocHandler)

	// pprof 路由
	mux.HandleFunc("/debug/pprof/", pp.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pp.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pp.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pp.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pp.Trace)

	s := &http.Server{Addr: ":8080", Handler: mux}
	fmt.Println("listening on :8080 (pprof at /debug/pprof/)")
	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}
```

**构建与运行**
```bash
go build -o demo ./main.go
./demo
# 健康检查（非回环地址）
curl -s http://$SERVER_ADDR:$SERVER_PORT/
# pprof 列表
curl -s http://$SERVER_ADDR:$SERVER_PORT/debug/pprof/
```

---

## 具体实验步骤

> 记录：硬件、CPU 与频率策略、内核版本、所用模式，以及关键输出与截图。

### 步骤 0：系统基线（**单机模式**，可加多机对照）
在**服务机**记录空闲性能基线（命令如下，具体功能请大家自行了解，这些命令可以分工完成，后续步骤中同理）：
```bash
mpstat -P ALL 1
iostat -xz 1
vmstat 1
sar -n DEV 1
ss -s
```
（可选）有**负载机**时：对 `$SERVER_ADDR` 进行 `ping/traceroute/iperf3` 记录网络基线。

---

### 步骤 1：轻载连通性（**多机模式**）
**目的**：验证端到端可达与基础延迟。  
在**负载机**执行下面命令，其中的参数可以根据实际情况调整以找到最真实的性能指标，后续实验同理：
```bash
wrk -t2 -c20 -d15s http://$SERVER_ADDR:$SERVER_PORT/
```
记录 RPS 与 p50/p95/p99。  
> 若仅一台机器：可暂用“网络隔离模式（见下）”。

---

### 步骤 2：CPU 瓶颈（/cpu，**单机模式**）
**目的**：定位算力热点。  
压测（示例在服务机执行），关注url中n的取值，可根据具体情况微调：
```bash
wrk -t4 -c50 -d30s "http://$SERVER_ADDR:$SERVER_PORT/cpu?n=42"
```
观测与火焰图（服务机）：
```bash
pid=$(pidof demo)
mpstat -P ALL 1
vmstat 1
pidstat -u -p $pid 1

# 下面三行命令用于绘制火焰图
sudo perf record -F 99 -g -p $pid -- sleep 30
sudo perf report
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > cpu.svg
```
**判据**：`vmstat r` 较大、某核≈100%、火焰图热点在 `fib` → **CPU 受限**。

---

### 步骤 3：磁盘 I/O 瓶颈（/io，**单机模式**）
**目的**：验证同步写/`fsync` 的 I/O 等待与吞吐受限。  
压测：
```bash
wrk -t4 -c50 -d30s "http://$SERVER_ADDR:$SERVER_PORT/io?bs_kb=1024&count=256"
```
观测：
```bash
iostat -xz 1
pidstat -d -p $(pidof demo) 1
sudo biolatency-bpfcc 1   # 可选直方图
```
**判据**：磁盘 `%util`、`await` 上升 → **I/O 受限**。

---

### 步骤 4：内存/GC 压力（/alloc，**单机模式**）
**目的**：观察高分配率与 GC 抖动。  
压测：
```bash
wrk -t4 -c100 -d30s "http://$SERVER_ADDR:$SERVER_PORT/alloc?kb=25600"
```
观测：
```bash
pid=$(pidof demo)
pidstat -r -p $pid 1
pmap -x $pid | tail -n 1
go tool pprof -top   http://$SERVER_ADDR:$SERVER_PORT/debug/pprof/profile?seconds=30
go tool pprof -http=:0 http://$SERVER_ADDR:$SERVER_PORT/debug/pprof/heap
```
**判据**：堆增大/GC 频繁/分配热点明显 → **内存/GC 瓶颈**。

---

### 步骤 5：系统调用与锁竞争（**单机模式**）
**目的**：定位 off-CPU 等待（锁、I/O、调度）。  
```bash
pid=$(pidof demo)
sudo strace -c -p $pid -f -qq -w -t -T -o /tmp/strace.txt -- sleep 30
sudo perf record -F 99 -g -p $pid -- sleep 30
# off-CPU 可选：
sudo offcputime-bpfcc -p $pid 10 > /tmp/offcpu.stacks
flamegraph.pl --color=io --countname us /tmp/offcpu.stacks > offcpu.svg
```
**判据**：`futex`/`semacquire` 等占比高 → **锁竞争/临界区过长**。

---

### 步骤 6：网络层状况与容量估算（**多机模式优先**；无二机→网络隔离）
**目的**：端到端容量与尾延迟评估（NIC/IRQ/队列/重传等）。  
在**负载机**：
```bash
wrk -t8 -c400 -d60s "http://$SERVER_ADDR:$SERVER_PORT/"
```
在**服务机**观测：
```bash
sar -n DEV 1
ss -tin
```
**Little’s Law**：`L ≈ λ × W`（`λ`=RPS，`W`=平均响应时间秒）→ 推断并发在途请求量，评估线程/协程规模。

---
## 单机场景下的配置优化（绑核、固定CPU频率）
```bash
# 进程绑核（分开核簇），下面例子假设有8个核，demo使用6个核，wrk使用2个核
taskset -c 2-7 ./demo
taskset -c 0-1 wrk -t2 -c200 -d60s http://127.0.0.1:8080/cpu?n=42

# 固定CPU频率（可选）
sudo cpupower frequency-set -g performance
```
## 网络隔离模式（单机也不用 127.0.0.1）

当只有一台服务器也需要做网络实验：将“客户端”与“服务端”放入不同 netns（`cli`/`srv`），服务仍监听 `:8080` 于 `srv`，并在**宿主机**通过 DNAT/SNAT 让 `cli` 以 **$SERVER_ADDR** 访问：

```bash
# 1) netns + veth
sudo ip netns add srv; sudo ip netns add cli
sudo ip link add veth-s type veth peer name veth-c
sudo ip link set veth-s netns srv; sudo ip link set veth-c netns cli
sudo ip netns exec srv ip addr add 10.10.0.2/24 dev veth-s
sudo ip netns exec cli ip addr add 10.10.0.1/24 dev veth-c
for ns in srv cli; do sudo ip netns exec $ns ip link set lo up; done
sudo ip netns exec srv ip link set veth-s up
sudo ip netns exec cli ip link set veth-c up

# 2) 在 srv ns 中运行服务
sudo ip netns exec srv ./demo

# 3) 宿主机开启转发 + NAT（iptables 版本）
sudo sysctl -w net.ipv4.ip_forward=1
# DNAT：将访问 $SERVER_ADDR:$SERVER_PORT 的流量转到 10.10.0.2:8080
sudo iptables -t nat -A PREROUTING -d $SERVER_ADDR -p tcp --dport $SERVER_PORT \
  -j DNAT --to-destination 10.10.0.2:$SERVER_PORT
# SNAT：将来自 10.10.0.0/24 回包源地址改为 $SERVER_ADDR，实现 hairpin
sudo iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -d 10.10.0.2 -p tcp --dport $SERVER_PORT \
  -j SNAT --to-source $SERVER_ADDR

# 4) 在 cli ns 里压测并注入网络条件
sudo ip netns exec cli wrk -t4 -c200 -d60s "http://$SERVER_ADDR:$SERVER_PORT/"
sudo ip netns exec cli tc qdisc add dev veth-c root netem delay 20ms rate 200mbit loss 0.1%
```
> 若使用 `nftables`，请写等价 `nft` 规则；实验结束记得清理 NAT。

---

## 火焰图与 pprof 速查

### A. CPU on-CPU（perf + FlameGraph）
```bash
pid=$(pidof demo)
sudo perf record -F 99 -g -p $pid -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl \
  --title "CPU on-CPU FlameGraph (demo)" --countname samples > cpu.svg
```

### B. off-CPU（等待/阻塞，BCC）
```bash
pid=$(pidof demo)
sudo offcputime-bpfcc -p $pid 15 > offcpu.stacks
flamegraph.pl --color=io --countname us --title "Off-CPU FlameGraph" \
  offcpu.stacks > offcpu.svg
```

### C. Go pprof（CPU/Heap）
```bash
# CPU 30s
go tool pprof -http=:0 http://$SERVER_ADDR:$SERVER_PORT/debug/pprof/profile?seconds=30
# Heap
go tool pprof -http=:0 http://$SERVER_ADDR:$SERVER_PORT/debug/pprof/heap
```

---

## 数据记录与分析模板
| 场景 | 模式（单机/隔离/多机） | 压测参数（t/c/d/URL） | RPS | p50/p95/p99 | CPU(总/核) | %util/await(磁盘) | 内存/GC要点 | 关键证据（perf/pprof/图） | 一句话结论 |
|---|---|---|---:|---|---|---|---|---|---|
| 基线 |  |  |  |  |  |  |  |  |  |
| 轻载连通 |  |  |  |  |  |  |  |  |  |
| CPU瓶颈 |  |  |  |  |  |  |  |  |  |
| I/O瓶颈 |  |  |  |  |  |  |  |  |  |
| 内存/GC |  |  |  |  |  |  |  |  |  |
| 锁/系统调度 |  |  |  |  |  |  |  |  |  |
| 网络容量 |  |  |  |  |  |  |  |  |  |
| 优化后 |  |  |  |  |  |  |  |  |  |

**典型判据速查**：  
- **CPU 受限**：某核≈100%、`vmstat r` > 核数、火焰图计算热点明显  
- **I/O 受限**：`iostat -xz` `%util` 高、`await` 高、`biolatency` 偏右  
- **锁竞争**：`perf/off-CPU` 中 `futex/semacquire` 占比高  
- **GC/内存抖动**：`pprof heap/profile` 分配热点、GC 频繁；`pidstat -r` 上升  
- **网络受限**：`sar -n DEV` 接近带宽；`ss -tin` 重传/队列异常

---

## 一次优化与复测（必做）
任选一项**最小改动**并复测：
- **CPU**：`fib` 改迭代/备忘录；降 `n`；调 `GOMAXPROCS`  
- **I/O**：缓冲/批量写；降低 `fsync` 频率；并发队列；更快介质  
- **内存**：缓冲复用/对象池；减少临时分配；调 `GOGC`  
- **锁**：缩小临界区；分段锁/读写锁；减少共享热点

报告包含：改动说明 → 复测数据 → 与基线/问题场景**定量对比**（如 RPS +35%、p95 -40%）与原因解释。

---

## 常见坑
- **`perf` 权限**：
  ```bash
  echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
  echo 0 | sudo tee /proc/sys/kernel/kptr_restrict
  ```
- **`pprof` 404**：自定义 mux 必须显式挂载 pprof（本示例已处理）。  
- **CPU 频率抖动**：用 `cpupower frequency-set -g performance` 降低抖动。  
- **端口未放通**：检查防火墙/云安全组是否放通 `$SERVER_PORT/tcp`。  
- **单机使用本机地址**：即使不是 127.0.0.1，依然可能不经真实 NIC，**不可据此做容量结论**；请用多机或网络隔离模式做对照。  
- **磁盘缓存影响**：I/O 实验可能被缓存掩盖，增大数据量或更严格同步（谨慎）。  
- **NUMA**：大内存/多核机器注意绑核/绑内存降低远程访问。
