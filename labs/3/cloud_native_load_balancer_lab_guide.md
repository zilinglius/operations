# 互联网产品开发与运维  
## 主题：云原生后端服务负载均衡 - 实验指导书

---

## 学习产出
- 熟悉静态（轮询、最少连接）与动态（基于应用指标自调节权重）负载均衡策略的优缺点。  
- 能够在 4 台 Linux 主机上完成“压测机 → 负载均衡器 → 2 个后端”的搭建、联调与观测。  
- 理解应用层可观测数据（延迟、错误率、并发度）与负载均衡决策之间的关系，能运用 `agent-check` 等机制做自适应调度。  
- 能够撰写包含拓扑、参数、数据、图表和分析结论的实验报告。

---

## 预备知识
- HTTP/TCP 基础、常见 4 层 & 7 层负载均衡模式。  
- Linux 基础运维能力：网络配置、服务启动、systemd、shell 脚本。  
- 基础的 Go 语言或至少能阅读 `labs/3/backend/main.go` 服务的代码结构。  
- 使用 `sar`、`ss`、`htop`、`tcpdump`、`wrk`/`hey` 等观测与压测工具的经验。  
- 了解 Prometheus/OpenMetrics 或 JSON 指标接口的基本格式。

---

## 实验环境准备

### 1. 拓扑规划

| 角色 | 主机名（示例） | 主要职责 | 关键端口 |
|---|---|---|---|
| 负载机 | `lab-load` | 执行 `wrk`/`hey` 压测，收集延迟分位值 | 无常驻端口 |
| 负载均衡器 | `lab-lb` | 运行 HAProxy（可选 Nginx/Envoy），统一入口 | `80/tcp、8404/tcp（stats）` |
| 后端 A | `lab-app-a` | 运行 `labs/3/backend` 服务实例 A | `8080/tcp`、`8090/tcp (agent)` |
| 后端 B | `lab-app-b` | 运行 `labs/3/backend` 服务实例 B | `8080/tcp`、`8090/tcp (agent)` |

> 需要至少两块真实网卡（或云环境内网）来观察网络队列、吞吐与连接状态。  
> 若暂时只能单机，请在文末“扩展任务”中参考 `netns + veth` 的替代方案，但正式评估请优先多机环境。

ASCII 逻辑拓扑：

```
              wrk / hey
             (lab-load)
                  |
            ┌─────▼─────┐
            │  HAProxy  │
            │  (lab-lb) │
            └─────┬─────┘
         Round Robin / 动态权重
          ┌────────┴────────┐
   labs/3/backend A    labs/3/backend B
       (lab-app-a)          (lab-app-b)
```

### 2. 操作系统与权限
- 推荐 Debian/Ubuntu 22.04 及以上，或 CentOS Stream 9。  
- 需要 root 或 sudo 权限安装软件、开放端口、配置 systemd/socket。  
- 关闭 SELinux/Firewalld 或正确放通端口；云环境记得配置安全组。

### 3. 基础依赖安装
在四台机器统一执行（按发行版调整命令）：

```bash
sudo apt update
sudo apt install -y \
  git curl wget make jq net-tools iproute2 iputils-ping \
  haproxy socat wrk htop sysstat bmon iftop \
  golang-go # 如果发行版仓库过旧，可从 https://go.dev/dl 下载二进制再解压
```

> 若无 `wrk`，可替换为 `hey` 或 `ab`，但需在报告中说明差异。

### 4. 后端服务工程
本实验提供了可调节负载与指标输出的后端服务，源码路径 `labs/3/backend/main.go`。

#### 4.1 代码解读要点
- 根路径 `/` 支持查询参数控制负载：  
  - `cpu_ms`、`sleep_ms`、`jitter_ms`：模拟 CPU/延迟。  
  - `fail_rate`：注入失败概率（0~1）。  
  - `payload_bytes`：扩充响应体大小。  
- `/metrics`：输出 JSON 指标（请求总数、错误比例、EWMA 延迟、p50/p90/p99 等）。  
- `/agent`：按当前 EWMA 延迟、错误率与并发度计算推荐权重，便于负载均衡器 `agent-check` 自调。  
- `/healthz`：基础存活探针。

#### 4.2 编译与运行
在两台后端机分别执行：

```bash
cd /path/to/repo/labs/3/backend
go build -o backend-server ./...

# 后端 A
./backend-server \
  -service api-lab \
  -instance app-a \
  -listen :8080 \
  -agent-listen :8090 \
  -target-latency-ms 80 \
  -max-inflight-safe 150 &

# 后端 B（可调更高的基线延迟以制造差异）
BASE_SLEEP_MS=20 TARGET_LATENCY_MS=120 \
./backend-server \
  -service api-lab \
  -instance app-b \
  -listen :8080 \
  -agent-listen :8090 \
  -latency-sample 128 &
```

关键环境变量（可选）：

| 变量 | 说明 | 默认值 |
|---|---|---|
| `BASE_CPU_MS` | 每次请求固定 CPU 自旋毫秒数 | 0 |
| `BASE_SLEEP_MS` | 固定休眠毫秒数 | 0 |
| `JITTER_MS` | 附加随机延迟（0~N） | 0 |
| `FAIL_RATE` | 固定故障概率（0~1） | 0 |
| `TARGET_LATENCY_MS` | `/agent` 权重判定的目标延迟 | 80 |
| `MAX_INFLIGHT_SAFE` | 超过该并发数会降低权重 | 120 |

> 启动后使用 `curl http://lab-app-a:8080/` 验证，并记录返回的 `request_id`、`metrics_hint` 等信息。

### 5. 负载均衡软件选择与配置
本指导书以 HAProxy 2.6+ 为示例，便于演示 `agent-check`。如需使用 Nginx/Envoy，可参考“扩展任务”自行对照。

#### 5.1 HAProxy 模板（静态实验起点）
`/etc/haproxy/haproxy.cfg`：

```haproxy
global
  log /dev/log local0
  log /dev/log local1 notice
  daemon
  stats socket /run/haproxy/admin.sock mode 666 level admin expose-fd listeners

defaults
  log     global
  mode    http
  option  httplog
  option  dontlognull
  timeout connect 5s
  timeout client  60s
  timeout server  60s

frontend fe_http
  bind *:80
  default_backend be_app

backend be_app
  balance roundrobin
  http-check send meth GET uri /healthz
  server app_a lab-app-a:8080 check
  server app_b lab-app-b:8080 check

listen stats
  bind *:8404
  stats enable
  stats uri /haproxy?stats
  stats refresh 5s
```

加载配置并验证：

```bash
sudo systemctl enable --now haproxy
sudo systemctl status haproxy
curl -I http://lab-lb/
```

> 建议开放 `8404` 给内网，仅实验账号访问。

### 6. 网络与安全配置
- 统一在四台主机上设置 `/etc/hosts`（或使用 DNS）确保互相能解析。  
- 负载机到后端直连需禁用；将默认路由指向 LB，确保所有流量经 LB。  
- 校验 `iptables`/`nftables`、安全组规则。建议暂时允许相互访问的 `tcp/80`, `tcp/8080`, `tcp/8404`, `tcp/22`。  
- 配置时间同步（`chrony`/`systemd-timesyncd`），方便对齐日志。

### 7. 基础观测面板
- 后端：`htop`, `pidstat`, `sar -n DEV 1`, `ss -tin`, `curl /metrics`。  
- LB：`echo "show servers state be_app" | sudo socat stdio /run/haproxy/admin.sock`。  
- 压测机：`wrk -t8 -c400 -d60s http://lab-lb/?cpu_ms=5`。  
- 可选：部署 node_exporter + Prometheus + Grafana，聚合 `/metrics` JSON 可借助 `telegraf`/`vector` 转换。

---

## 实验一：静态负载均衡

### 实验目的
验证轮询 / 最少连接等静态算法在不同后端性能差异下的请求分布、延迟和系统指标表现。

### 步骤
1. **基准对照**  
   - 在负载机直接访问后端 A/B（绕过 LB）：  
     ```bash
     wrk -t4 -c64 -d60s http://lab-app-a:8080/
     wrk -t4 -c64 -d60s "http://lab-app-b:8080/?sleep_ms=10"
     ```  
   - 记录 RPS、p50/p95/p99、CPU 占用、`/metrics` 中的 `ewma_latency_ms`。

2. **轮询策略验证**  
   - 使用前述 `haproxy.cfg`（`balance roundrobin`）。  
   - 在负载机发起混合请求：  
     ```bash
     wrk -t8 -c200 -d120s --timeout 4s http://lab-lb/?cpu_ms=8&payload_bytes=256
     ```  
   - 同时抓取：  
     - `curl http://lab-lb:8404/haproxy\?stats` 查看后端连接数。  
     - `curl http://lab-app-a:8080/metrics`、`lab-app-b:8080/metrics`。  
     - `sar -u 1`、`sar -n DEV 1`。

3. **最少连接策略**  
   - 修改 `backend be_app` 为 `balance leastconn`，重载 HAProxy：  
     ```bash
     sudo systemctl reload haproxy
     ```  
   - 在后端 B 重启服务并设置更高延迟/错误率（示例）：  
     ```bash
     sudo pkill backend-server || true
     BASE_SLEEP_MS=40 FAIL_RATE=0.02 ./backend-server \
       -service api-lab -instance app-b -listen :8080 agent-listen :8090 &
     ```  
   - 重复压测，观察权重与连接分布是否贴近预期。

4. **数据整理**  
   - 按下表记录实验数据：

| 场景 | LB 策略 | 压测参数 (t/c/d) | 平均 RPS | p50/p95/p99 (ms) | A/B CPU (%) | 错误率 | 备注 |
|---|---|---|---|---|---|---|---|
| 直连 A | - |  |  |  |  |  |  |
| 直连 B | - |  |  |  |  |  |  |
| LB 轮询 | roundrobin |  |  |  |  |  |  |
| LB 最少连接 | leastconn |  |  |  |  |  |  |

### 思考题
- 当后端 B 响应慢但无错误时，`roundrobin` 与 `leastconn` 的分配差异？  
- 观察 `/metrics`：`ewma_latency_ms` 与负载均衡分布是否存在明显相关性？  
- 静态策略在突发失败/抖动时的局限是什么？

---

## 实验二：动态负载均衡（基于应用指标自调节）

### 实验目的
利用后端 `/agent` 接口和 HAProxy `agent-check` 机制，根据实时延迟、错误率及并发量自动调整服务器权重，实现动态调度。

### 配置步骤
1. **启用 agent-check**  
   在 `haproxy.cfg` 中为后端添加：

   ```haproxy
   backend be_app
     balance roundrobin
     option httpchk GET /healthz
     default-server agent-check agent-port 8090 agent-inter 1s
     server app_a lab-app-a:8080 check weight 50 agent-addr lab-app-a
     server app_b lab-app-b:8080 check weight 50 agent-addr lab-app-b
   ```

   重载 HAProxy 并确认 `show servers state be_app` 中可以看到 `agent` 权重列。

2. **模拟不均衡负载**  
   - 让后端 B 保持较高延迟：`BASE_SLEEP_MS=30` 启动。  
   - 在负载机持续压测：  
     ```bash
     wrk -t16 -c400 -d180s --timeout 5s http://lab-lb/?cpu_ms=10
     ```  
   - 周期性查看权重变化：  
     ```bash
     watch -n1 "echo 'show servers state be_app' | sudo socat stdio /run/haproxy/admin.sock | awk '{print \$1,\$5,\$8,\$9,\$18}'"
     ```

3. **动态调节验证**  
   - 期间在后端 A 注入故障（重启为高失败率模式，可在实验结束后恢复）：  
     ```bash
     sudo pkill backend-server || true
     FAIL_RATE=0.2 ./backend-server \
       -service api-lab -instance app-a -listen :8080 -agent-listen :8090 &
     ```  
   - 观察 `/agent` 返回值：  
     ```bash
     curl http://lab-app-a:8080/agent
     ```  
   - 预期：权重迅速降低，必要时被标记 `down`，流量转移至后端 B。

4. **恢复与稳态**  
   - 结束实验时在后端 A/B 使用默认参数重新启动 `backend-server`，确认 `/agent` 恢复为 `up 100`。  
   - 对比压测数据：动态调节是否降低整体 p95/p99，错误率是否下降。

5. **实验记录表**

| 时间点 | app_a `/agent` | app_b `/agent` | HAProxy 权重 | RPS | p95 (ms) | 错误率 | 备注 |
|---|---|---|---|---|---|---|---|
| t0 (稳态) |  |  |  |  |  |  |  |
| t1 (注入故障) |  |  |  |  |  |  |  |
| t2 (恢复) |  |  |  |  |  |  |  |

### 深入思考
- 设计新的权重策略：将 `/metrics` 中的 p99、inflight 同时纳入评估是否更合理？  
- 若目标延迟设定过低或过高，对权重波动有何影响？如何避免频繁抖动？  
- 若希望 LB 同时考虑成本/能耗等因素，可以如何扩展 `/agent` 的响应？

---

## 扩展任务（有兴趣可以尝试）
- **方案一：Envoy 动态发现**  
  使用 xDS 静态引导 + EDS API，编写脚本将 `/metrics` 结果转换为 Envoy `endpoint` 权重。  
- **方案二：Nginx + Lua**  
  基于 OpenResty，调用 `/metrics` 并在请求前动态选择上游。  

---

## 数据整理与实验报告内容参考
1. **内容结构**  
   - 实验背景与目标；拓扑与硬件规格；软件版本。  
   - 静态与动态实验流程、参数、截图/图表。  
   - 数据对照（RPS、分位延迟、错误率、CPU/Mem、队列长度、`/metrics` 关键字段）。  
   - 分析与结论：指出静态策略的问题、动态策略的改进效果及不足。  
   - 附录：脚本、配置、问题排查。

2. **可视化建议**  
   - 折线：时间-权重、时间-延迟。  
   - 柱状：实验前后 RPS/p99。  
   - 表格：关键指标对比。

3. **重点提示**  
   - 数据完整性（是否覆盖多个场景、指标）。  
   - 分析深度（是否结合 `/metrics`、HAProxy stats、系统指标做因果推断）。  
   - 可用性（说明异常与排错过程，如连接数过高、TIME_WAIT、socket backlog 等）。

---

## 常见排错清单
- HAProxy 无法连接后端：检查防火墙、`/etc/hosts`、`server app_a` 主机名是否可解析。  
- `/agent` 不生效：确认 HAProxy 版本 ≥2.0，`agent-addr`、`agent-port` 与后端监听一致。  
- 指标不更新：后端没有流量或 `latency-sample` 太小导致抖动，酌情增大或改用 Prometheus 拉取。  
- 压测超时：调大 `wrk --timeout`，或在 HAProxy `timeout server` 上调至 120s。  
- 权重频繁跳动：调高 `TARGET_LATENCY_MS`、降低 `fail_rate`、或修改代码中 EWMA 系数。

---

## 附录 A：快速检查脚本
```bash
# 查看 HAProxy 后端实时状态
echo "show servers state be_app" | sudo socat stdio /run/haproxy/admin.sock

# 拉取后端指标
for host in lab-app-a lab-app-b; do
  echo "===> $host"
  curl -s http://$host:8080/metrics | jq '.counters, .gauges, .latency'
done

# 压测模板（按需调整 t/c/d）
wrk -t8 -c256 -d90s --timeout 4s http://lab-lb/?cpu_ms=12&payload_bytes=512
```

---

完成以上实验后，应能清晰回答：
1. 为什么仅靠静态轮询在异构后端时会出现“慢节点拖累整体”现象？  
2. 如何基于应用指标动态调整负载均衡策略，避免盲目放大流量？  
3. `labs/3/backend` 提供的指标还能如何扩展（如导出 Prometheus 指标、加入流量标签）以对接企业级监控系统？

