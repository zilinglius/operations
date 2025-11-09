package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// latencyPercentiles 保存最近延迟样本的关键百分位指标，帮助快速定位尾部延迟。
type latencyPercentiles struct {
	P50 float64 `json:"p50_ms"`
	P90 float64 `json:"p90_ms"`
	P99 float64 `json:"p99_ms"`
}

// latencySnapshot 汇总延迟统计信息，包括样本数量、平均值、指数加权平均等。
type latencySnapshot struct {
	SampleSize int               `json:"sample_size"`
	Average    float64           `json:"average_ms"`
	EWMA       float64           `json:"ewma_ms"`
	Percentile latencyPercentiles `json:"percentiles"`
}

// counterSnapshot 表示计数器指标，用于记录总请求数和错误响应数。
type counterSnapshot struct {
	TotalRequests uint64 `json:"total_requests"`
	ErrorResponses uint64 `json:"error_responses"`
}

// gaugeSnapshot 存储类似“当前并发数”这类瞬时指标。
type gaugeSnapshot struct {
	Inflight int64 `json:"inflight"`
}

// runtimeSnapshot 反映 Go 运行时状态，便于监控服务自身健康状况。
type runtimeSnapshot struct {
	UptimeSeconds    int64  `json:"uptime_seconds"`
	GoVersion        string `json:"go_version"`
	CPUCount         int    `json:"cpu_count"`
	Goroutines       int    `json:"goroutines"`
	LastGCUnixMillis int64  `json:"last_gc_unix_millis"`
}

// metricsSnapshot 将所有指标打包成一句话，便于一次性序列化返回。
type metricsSnapshot struct {
	Service   string           `json:"service"`
	Instance  string           `json:"instance"`
	Version   string           `json:"version"`
	Host      string           `json:"host"`
	Timestamp time.Time        `json:"timestamp"`
	Counters  counterSnapshot  `json:"counters"`
	Gauges    gaugeSnapshot    `json:"gauges"`
	Latency   latencySnapshot  `json:"latency"`
	Runtime   runtimeSnapshot  `json:"runtime"`
}

// backendResponse 是后端对外暴露的响应结构，便于前端或实验脚本消费。
type backendResponse struct {
	Service     string                 `json:"service"`
	Instance    string                 `json:"instance"`
	Version     string                 `json:"version"`
	Host        string                 `json:"host"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   string                 `json:"request_id"`
	Route       string                 `json:"route"`
	DurationMS  float64                `json:"duration_ms"`
	Status      int                    `json:"status"`
	Workload    map[string]any         `json:"workload"`
	MetricsHint map[string]any         `json:"metrics_hint"`
	Payload     string                 `json:"payload,omitempty"`
}

// metricsStore 管理内存中的监控指标，使用互斥锁确保并发安全。
type metricsStore struct {
	startTime time.Time

	inflight atomic.Int64

	mu               sync.Mutex
	totalRequests    uint64
	errorResponses   uint64
	totalLatency     time.Duration
	ewmaLatencyMs    float64
	latencySamples   []time.Duration // 使用环形数组存储最近的延迟样本
	latencyCount     int             // 当前有效样本数量
	latencyWriteIndex int            // 环形写入索引
}

// newMetricsStore 创建指标存储对象，并为延迟样本预留空间。
func newMetricsStore(sampleSize int) *metricsStore {
	if sampleSize <= 0 {
		sampleSize = 64
	}
	return &metricsStore{
		startTime:      time.Now(),
		latencySamples: make([]time.Duration, sampleSize),
	}
}

// observe 记录一次请求的耗时和状态，用于后续计算各种延迟和错误率指标。
func (ms *metricsStore) observe(d time.Duration, err bool) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.totalRequests++
	ms.totalLatency += d
	if err {
		ms.errorResponses++
	}

	durationMs := float64(d) / float64(time.Millisecond)
	const alpha = 0.25
	if ms.ewmaLatencyMs == 0 {
		ms.ewmaLatencyMs = durationMs
	} else {
		ms.ewmaLatencyMs = alpha*durationMs + (1-alpha)*ms.ewmaLatencyMs
	}

	if len(ms.latencySamples) > 0 {
		ms.latencySamples[ms.latencyWriteIndex] = d
		ms.latencyWriteIndex = (ms.latencyWriteIndex + 1) % len(ms.latencySamples)
		if ms.latencyCount < len(ms.latencySamples) {
			ms.latencyCount++
		}
	}
}

// snapshot 在当前状态下生成一份只读的指标快照，避免对外暴露内部锁。
func (ms *metricsStore) snapshot(meta metadata) metricsSnapshot {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var avg float64
	if ms.totalRequests > 0 {
		avg = float64(ms.totalLatency/time.Microsecond) / float64(ms.totalRequests) / 1000.0
	}

	latencyCopy := make([]time.Duration, ms.latencyCount)
	if ms.latencyCount > 0 {
		for i := 0; i < ms.latencyCount; i++ {
			idx := (ms.latencyWriteIndex - ms.latencyCount + i + len(ms.latencySamples)) % len(ms.latencySamples)
			latencyCopy[i] = ms.latencySamples[idx]
		}
		sort.Slice(latencyCopy, func(i, j int) bool {
			return latencyCopy[i] < latencyCopy[j]
		})
	}

	getPercentile := func(p float64) float64 {
		if len(latencyCopy) == 0 {
			return 0
		}
		if p <= 0 {
			return float64(latencyCopy[0]) / float64(time.Millisecond)
		}
		if p >= 100 {
			return float64(latencyCopy[len(latencyCopy)-1]) / float64(time.Millisecond)
		}
		rank := p / 100 * float64(len(latencyCopy)-1)
		lower := int(math.Floor(rank))
		upper := int(math.Ceil(rank))
		if lower == upper {
			return float64(latencyCopy[lower]) / float64(time.Millisecond)
		}
		weight := rank - float64(lower)
		lowVal := float64(latencyCopy[lower]) / float64(time.Millisecond)
		highVal := float64(latencyCopy[upper]) / float64(time.Millisecond)
		return lowVal + (highVal-lowVal)*weight
	}

	var mstat runtime.MemStats
	runtime.ReadMemStats(&mstat)
	lastGC := int64(0)
	if mstat.LastGC > 0 {
		lastGC = int64(time.Unix(0, int64(mstat.LastGC)).UnixMilli())
	}

	return metricsSnapshot{
		Service:   meta.service,
		Instance:  meta.instance,
		Version:   meta.version,
		Host:      meta.host,
		Timestamp: time.Now().UTC(),
		Counters: counterSnapshot{
			TotalRequests: ms.totalRequests,
			ErrorResponses: ms.errorResponses,
		},
		Gauges: gaugeSnapshot{
			Inflight: ms.inflight.Load(),
		},
		Latency: latencySnapshot{
			SampleSize: len(ms.latencySamples),
			Average:    avg,
			EWMA:       ms.ewmaLatencyMs,
			Percentile: latencyPercentiles{
				P50: getPercentile(50),
				P90: getPercentile(90),
				P99: getPercentile(99),
			},
		},
		Runtime: runtimeSnapshot{
			UptimeSeconds:    int64(time.Since(ms.startTime).Round(time.Second) / time.Second),
			GoVersion:        runtime.Version(),
			CPUCount:         runtime.NumCPU(),
			Goroutines:       runtime.NumGoroutine(),
			LastGCUnixMillis: lastGC,
		},
	}
}

// metadata 表示服务元信息，用于统一填充响应与指标中的身份字段。
type metadata struct {
	service string
	instance string
	version string
	host string
	defaultPayload string
}

// workloadConfig 描述一次请求的工作负载参数，既可以来自环境变量，也可以被查询参数覆盖。
type workloadConfig struct {
	baseCPUMillis    int
	baseSleepMillis  int
	maxPayloadBytes  int
	defaultPayload   string
	jitterMillis     int
	failRate         float64
	targetLatencyMs  float64
	maxInflightSafe  int64
}

// envOrDefault 封装“环境变量覆盖默认值”的常见模式。
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseEnvInt 尝试读取整数环境变量，失败时回落到默认值。
func parseEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return def
}

// parseEnvFloat 解析浮点数环境变量。
func parseEnvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			return parsed
		}
	}
	return def
}

// parseEnvInt64 解析 64 位整数环境变量。
func parseEnvInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			return parsed
		}
	}
	return def
}

// parsePositiveInt 提供对正整数的统一校验逻辑，在多个参数场景中复用。
func parsePositiveInt(value string) (int, error) {
	if value == "" {
		return 0, errors.New("empty")
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if i < 0 {
		return 0, fmt.Errorf("negative: %d", i)
	}
	return i, nil
}

// spin 模拟 CPU 运算，通过忙等消耗指定毫秒数的 CPU 时间。
func spin(cpuMillis int) {
	if cpuMillis <= 0 {
		return
	}
	target := time.Now().Add(time.Duration(cpuMillis) * time.Millisecond)
	for time.Now().Before(target) {
	}
}

// randomSleep 模拟 IO 等待，直接调用 time.Sleep。
func randomSleep(extraMillis int) {
	if extraMillis <= 0 {
		return
	}
	time.Sleep(time.Duration(extraMillis) * time.Millisecond)
}

// clamp 将数值限制在闭区间 [min, max] 内。
func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// clampFloat 为浮点数版本的 clamp。
func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// newBackendResponse 根据当前请求生成响应体，同时附带一份指标提示信息。
func newBackendResponse(meta metadata, reqID string, route string, status int, duration time.Duration, workload map[string]any, payload string, snapshot metricsSnapshot) backendResponse {
	return backendResponse{
		Service:     meta.service,
		Instance:    meta.instance,
		Version:     meta.version,
		Host:        meta.host,
		Timestamp:   time.Now().UTC(),
		RequestID:   reqID,
		Route:       route,
		DurationMS:  float64(duration/time.Microsecond) / 1000.0,
		Status:      status,
		Workload:    workload,
		MetricsHint: map[string]any{
			"ewma_latency_ms": snapshot.Latency.EWMA,
			"avg_latency_ms":  snapshot.Latency.Average,
			"inflight":        snapshot.Gauges.Inflight,
		},
		Payload: payload,
	}
}

// sanitizeFailRate 确保失败率在 0~1 之间，避免出现非法数值。
func sanitizeFailRate(value float64) float64 {
	value = clampFloat(value, 0, 1)
	return value
}

// recommendedWeight 根据当前服务状态计算建议的负载均衡权重，并附带原因标签。
func recommendedWeight(snapshot metricsSnapshot, cfg workloadConfig) (int, string) {
	if snapshot.Counters.TotalRequests == 0 {
		return 100, "bootstrap"
	}

	// errorRatio 观察近期错误比例，用于快速降权。
	errorRatio := 0.0
	if snapshot.Counters.TotalRequests > 0 {
		errorRatio = float64(snapshot.Counters.ErrorResponses) / float64(snapshot.Counters.TotalRequests)
	}

	weight := 100
	reason := "healthy"

	if errorRatio > 0.10 {
		return 1, "error_ratio_gt_10pct"
	}
	if errorRatio > 0.05 {
		weight = 20
		reason = "error_ratio_gt_5pct"
	}

	// 以 EWMA 作为核心延迟指标，若采样不足则回退到简单平均。
	latency := snapshot.Latency.EWMA
	if latency <= 0 {
		latency = snapshot.Latency.Average
	}
	if latency <= 0 {
		return weight, reason
	}

	target := cfg.targetLatencyMs
	if target <= 0 {
		target = 50
	}

	switch {
	case latency > target*2.5:
		weight = min(weight, 10)
		reason = "ewma_gt_2.5x_target"
	case latency > target*2.0:
		weight = min(weight, 20)
		reason = "ewma_gt_2x_target"
	case latency > target*1.5:
		weight = min(weight, 40)
		reason = "ewma_gt_1.5x_target"
	case latency > target*1.2:
		weight = min(weight, 60)
		reason = "ewma_gt_1.2x_target"
	}

	// 并发数超过安全阈值时也要降权，避免雪崩。
	if cfg.maxInflightSafe > 0 && snapshot.Gauges.Inflight > cfg.maxInflightSafe {
		weight = min(weight, 30)
		reason = "inflight_exceeds_safe_limit"
	}

	if weight < 1 {
		weight = 1
	}
	return weight, reason
}

// min 返回两个整数中的较小值。
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// makePayload 根据请求要求生成响应体字符串，超出部分用随机字母补齐。
func makePayload(base string, bytes int) string {
	if bytes <= 0 {
		return base
	}
	if bytes > 1<<20 {
		bytes = 1 << 20
	}
	if len(base) >= bytes {
		return base[:bytes]
	}
	buf := make([]byte, bytes)
	copy(buf, base)
	for i := len(base); i < bytes; i++ {
		buf[i] = byte('a' + rand.Intn(26))
	}
	return string(buf)
}

// traceWorkload 将本次请求的配置透传到响应中，便于实验时回溯负载参数。
func traceWorkload(cfg workloadConfig, query map[string]string) map[string]any {
	workload := map[string]any{
		"base_cpu_ms":   cfg.baseCPUMillis,
		"base_sleep_ms": cfg.baseSleepMillis,
		"fail_rate":     cfg.failRate,
		"jitter_ms":     cfg.jitterMillis,
	}
	for k, v := range query {
		workload[k] = v
	}
	return workload
}

// parseQueryParams 将 URL 查询参数平铺为 map，便于后续覆盖默认配置。
func parseQueryParams(r *http.Request) map[string]string {
	q := map[string]string{}
	for key, values := range r.URL.Query() {
		if len(values) == 0 {
			continue
		}
		q[key] = values[0]
	}
	return q
}

// main 中组装服务器配置、注册路由，并启动 HTTP 服务。
func main() {
	// flag 区域定义 CLI 参数，也支持环境变量覆盖，便于在容器或脚本中注入配置。
	flagService := flag.String("service", envOrDefault("SERVICE_NAME", "lb-lab-backend"), "logical service name")
	flagInstance := flag.String("instance", envOrDefault("INSTANCE_ID", ""), "instance identifier")
	flagVersion := flag.String("version", envOrDefault("SERVICE_VERSION", "v1"), "service version tag")
	flagListen := flag.String("listen", envOrDefault("LISTEN_ADDR", ":8080"), "listen address")
	flagSampleSize := flag.Int("latency-sample", parseEnvInt("LATENCY_SAMPLE_SIZE", 64), "latency sample size for percentile estimates")
	flagTargetLatency := flag.Float64("target-latency-ms", parseEnvFloat("TARGET_LATENCY_MS", 80), "target latency for adaptive weight calculation")
	flagMaxInflight := flag.Int64("max-inflight-safe", parseEnvInt64("MAX_INFLIGHT_SAFE", 120), "in-flight request threshold before reducing weight")
	flag.Parse()

	host, err := os.Hostname()
	if err != nil {
		host = "unknown-host"
	}

	instance := *flagInstance
	if instance == "" {
		instance = host
	}

	// meta 存储服务身份信息，用于响应与指标的统一输出。
	meta := metadata{
		service: envOrDefault("SERVICE_NAME", *flagService),
		instance: instance,
		version: envOrDefault("SERVICE_VERSION", *flagVersion),
		host: host,
		defaultPayload: envOrDefault("DEFAULT_PAYLOAD", "hello from backend"),
	}

	// cfg 描述工作负载参数，既可以全局配置，也允许每次请求通过查询参数调整。
	cfg := workloadConfig{
		baseCPUMillis:   parseEnvInt("BASE_CPU_MS", 0),
		baseSleepMillis: parseEnvInt("BASE_SLEEP_MS", 0),
		maxPayloadBytes: parseEnvInt("MAX_PAYLOAD_BYTES", 1024),
		defaultPayload:  meta.defaultPayload,
		jitterMillis:    parseEnvInt("JITTER_MS", 0),
		failRate:        sanitizeFailRate(parseEnvFloat("FAIL_RATE", 0)),
		targetLatencyMs: *flagTargetLatency,
		maxInflightSafe: *flagMaxInflight,
	}

	// 指标存储负责聚合延迟、错误率等信息。
	ms := newMetricsStore(*flagSampleSize)
	// 随机数种子确保每个实例的行为独立。
	rand.Seed(time.Now().UnixNano())

	// 主处理函数：接收根路径请求，模拟 CPU/IO 开销并返回 JSON。
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ms.inflight.Add(1)

		// 查询参数允许在一次请求内覆盖默认工作负载。
		queryParams := parseQueryParams(r)

		cpuMs := cfg.baseCPUMillis
		if v, ok := queryParams["cpu_ms"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				cpuMs = parsed
			}
		}

		sleepMs := cfg.baseSleepMillis
		if v, ok := queryParams["sleep_ms"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				sleepMs = parsed
			}
		}

		jitterMs := cfg.jitterMillis
		if v, ok := queryParams["jitter_ms"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				jitterMs = parsed
			}
		}

		payloadBytes := cfg.maxPayloadBytes
		if v, ok := queryParams["payload_bytes"]; ok {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				payloadBytes = clamp(parsed, 0, cfg.maxPayloadBytes)
			}
		}

		failRate := cfg.failRate
		if v, ok := queryParams["fail_rate"]; ok {
			if parsed, err := strconv.ParseFloat(v, 64); err == nil {
				failRate = sanitizeFailRate(parsed)
			}
		}

		spin(cpuMs)
		if jitterMs > 0 {
			randomSleep(rand.Intn(jitterMs + 1))
		}
		randomSleep(sleepMs)

		// 按失败率注入 500 错误，以便观察负载均衡的容错策略。
		status := http.StatusOK
		if failRate > 0 && rand.Float64() < failRate {
			status = http.StatusInternalServerError
		}

		duration := time.Since(start)
		// 记录指标并减少正在处理的请求计数。
		ms.observe(duration, status >= 500)
		currentInflight := ms.inflight.Add(-1)

		snapshot := ms.snapshot(meta)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-Instance", meta.instance)
		w.Header().Set("X-Backend-Version", meta.version)
		w.Header().Set("X-Backend-Inflight", strconv.FormatInt(currentInflight, 10))
		w.WriteHeader(status)

		resp := newBackendResponse(meta, fmt.Sprintf("%s-%d", meta.instance, rand.Int63()), r.URL.Path, status, duration, traceWorkload(cfg, queryParams), makePayload(meta.defaultPayload, payloadBytes), snapshot)

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode response: %v", err)
		}
	})

	// /healthz 用于平台探活，返回最小必要信息即可。
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service":   meta.service,
			"instance":  meta.instance,
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
		})
	})

	// /metrics 暴露当前指标，用于实验中观察服务行为。
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		snapshot := ms.snapshot(meta)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// /agent 模拟负载均衡探针，根据指标返回 up/down 或权重建议。
	http.HandleFunc("/agent", func(w http.ResponseWriter, r *http.Request) {
		snapshot := ms.snapshot(meta)
		weight, reason := recommendedWeight(snapshot, cfg)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if snapshot.Counters.TotalRequests == 0 {
			fmt.Fprintf(w, "up %d\n", weight)
			return
		}
		if snapshot.Counters.ErrorResponses > 0 && float64(snapshot.Counters.ErrorResponses)/float64(snapshot.Counters.TotalRequests) > 0.25 {
			fmt.Fprintf(w, "down\n")
			return
		}
		fmt.Fprintf(w, "up %d # %s\n", weight, reason)
	})

	server := &http.Server{
		Addr:              *flagListen,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// 先手动监听端口，方便在监听失败时打印详细错误。
	listener, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *flagListen, err)
	}

	log.Printf("listening on %s service=%s instance=%s version=%s", *flagListen, meta.service, meta.instance, meta.version)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}
