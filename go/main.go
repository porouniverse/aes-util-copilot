// Go 侧联合测试驱动：调用真实库 github.com/porouniverse/aes-util-copilot
//
// 用法：
//
//	joint-go encrypt --cases out/cases.tsv --out out/ct_go.tsv --workers 2
//	joint-go verify  --cases out/cases.tsv --ct out/ct_go.tsv,out/ct_js.tsv,out/ct_java.tsv --out out/verify_go.tsv --workers 2
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aesutil "github.com/porouniverse/aes-util-copilot"
)

// sourceOrder 固定三语言密文的顺序，verify 输出的 mask 位序与之一一对应
var sourceOrder = []string{"go", "js", "java"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: joint-go encrypt|verify [options]")
		os.Exit(2)
	}
	mode := os.Args[1]
	opts := parseOpts(os.Args[2:])
	ids, passwords, plaintexts := readCases(opts["cases"])
	workers := atoi(opts["workers"], 4)
	switch mode {
	case "encrypt":
		runEncrypt(ids, passwords, plaintexts, workers, opts["out"])
	case "verify":
		runVerify(ids, passwords, plaintexts, workers, strings.Split(opts["ct"], ","), opts["out"])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", mode)
		os.Exit(2)
	}
}

// ---------------- 加密 ----------------

func runEncrypt(ids []int, passwords, plaintexts []string, workers int, outPath string) {
	n := len(ids)
	cts := make([]string, n)
	errs := make([]string, n)
	ms := make([]float64, n)

	parallelFor(n, workers, func(i int) {
		start := time.Now()
		ct, err := aesutil.EncryptHex(passwords[i], plaintexts[i])
		ms[i] = float64(time.Since(start).Microseconds()) / 1000.0
		if err != nil {
			errs[i] = err.Error()
		} else {
			cts[i] = ct
		}
	}, "go", "encrypt")

	writeFile(outPath, n, func(i int) string {
		return fmt.Sprintf("%d\t%s\t%.3f\n", ids[i], cts[i], ms[i])
	})
}

// ---------------- 交叉解密验证 ----------------

func runVerify(ids []int, passwords, plaintexts []string, workers int, ctPaths []string, outPath string) {
	n := len(ids)
	maxID := 0
	for _, id := range ids {
		if id > maxID {
			maxID = id
		}
	}

	// ctSets[sourceIndex][caseID] = hex 密文
	ctSets := make([][]string, len(sourceOrder))
	for s := range sourceOrder {
		ctSets[s] = readCt(ctPaths[s], maxID)
	}

	masks := make([]int, n)
	msBySource := make([][3]float64, n)
	errs := make([]string, n)

	parallelFor(n, workers, func(i int) {
		mask := 0
		var msgs []string
		for s := 0; s < len(sourceOrder); s++ {
			ct := ctSets[s][ids[i]]
			start := time.Now()
			got, err := aesutil.DecryptStr(passwords[i], ct)
			msBySource[i][s] = float64(time.Since(start).Microseconds()) / 1000.0
			if err != nil {
				msgs = append(msgs, sourceOrder[s]+"="+err.Error())
				continue
			}
			if got != plaintexts[i] {
				msgs = append(msgs, sourceOrder[s]+"=plaintext mismatch")
				continue
			}
			mask |= 1 << s
		}
		masks[i] = mask
		if len(msgs) > 0 {
			errs[i] = strings.Join(msgs, "; ")
		}
	}, "go", "verify")

	writeFile(outPath, n, func(i int) string {
		e := errs[i]
		if e == "" {
			e = "-"
		} else {
			e = base64.StdEncoding.EncodeToString([]byte(e))
		}
		return fmt.Sprintf("%d\t%d\t%.3f\t%.3f\t%.3f\t%s\n",
			ids[i], masks[i], msBySource[i][0], msBySource[i][1], msBySource[i][2], e)
	})
}

// ---------------- 并发执行 ----------------

func parallelFor(n, workers int, fn func(i int), lang, phase string) {
	if workers < 1 {
		workers = 1
	}
	var next int64
	var done int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&next, 1)) - 1
				if i >= n {
					return
				}
				fn(i)
				d := atomic.AddInt64(&done, 1)
				if d%5000 == 0 || int(d) == n {
					fmt.Fprintf(os.Stderr, "[%s][%s] %d/%d\n", lang, phase, d, n)
				}
			}
		}()
	}
	wg.Wait()
}

// ---------------- IO ----------------

func readCases(path string) ([]int, []string, []string) {
	f, err := os.Open(path)
	if err != nil {
		fatal("open cases: " + err.Error())
	}
	defer f.Close()

	var ids []int
	var passwords, plaintexts []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			if strings.HasPrefix(line, "id\t") {
				continue
			}
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			fatal("bad cases line: " + line[:min(len(line), 80)])
		}
		id, _ := strconv.Atoi(parts[0])
		pw, _ := base64.StdEncoding.DecodeString(parts[1])
		pt, _ := base64.StdEncoding.DecodeString(parts[2])
		ids = append(ids, id)
		passwords = append(passwords, string(pw))
		plaintexts = append(plaintexts, string(pt))
	}
	if err := sc.Err(); err != nil {
		fatal("read cases: " + err.Error())
	}
	return ids, passwords, plaintexts
}

func readCt(path string, maxID int) []string {
	f, err := os.Open(path)
	if err != nil {
		fatal("open ct " + path + ": " + err.Error())
	}
	defer f.Close()

	out := make([]string, maxID+1)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			if strings.HasPrefix(line, "id\t") {
				continue
			}
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			fatal("bad ct line in " + path)
		}
		id, _ := strconv.Atoi(parts[0])
		out[id] = parts[1]
	}
	if err := sc.Err(); err != nil {
		fatal("read ct " + path + ": " + err.Error())
	}
	return out
}

func writeFile(path string, n int, row func(i int) string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatal("mkdir: " + err.Error())
	}
	f, err := os.Create(path)
	if err != nil {
		fatal("create out: " + err.Error())
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	for i := 0; i < n; i++ {
		w.WriteString(row(i))
	}
	if err := w.Flush(); err != nil {
		fatal("flush: " + err.Error())
	}
}

func parseOpts(args []string) map[string]string {
	o := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			k := strings.TrimPrefix(a, "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				o[k] = args[i+1]
				i++
			} else {
				o[k] = "true"
			}
		}
	}
	return o
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "FATAL:", msg)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
