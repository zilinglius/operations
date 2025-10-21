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
