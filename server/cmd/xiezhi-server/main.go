// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/auth"
	"github.com/xycxmz/xiezhi-public/server/internal/deadman"
	"github.com/xycxmz/xiezhi-public/server/internal/firstseen"
	fspg "github.com/xycxmz/xiezhi-public/server/internal/firstseen/pgstore"
	"github.com/xycxmz/xiezhi-public/server/internal/httpapi"
	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
	"github.com/xycxmz/xiezhi-public/server/internal/intent"
	"github.com/xycxmz/xiezhi-public/server/internal/llm"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
	"github.com/xycxmz/xiezhi-public/server/internal/rules"
	"github.com/xycxmz/xiezhi-public/server/internal/session"
	sspg "github.com/xycxmz/xiezhi-public/server/internal/session/pgstore"
	"github.com/xycxmz/xiezhi-public/server/internal/sink"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

var buildVersion = "0.1.0"

const (
	natsSubject  = "xiezhi.events"
	queueSize    = 8192
	batchMaxRows = 1000
	batchFlush   = time.Second
	windowCap    = 8192
)

// hostname 取本机主机名（degraded webhook 载荷用），失败退回 unknown。
func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("xiezhi-server %s %s/%s\n", buildVersion, runtime.GOOS, runtime.GOARCH)
		return
	}
	if err := run(); err != nil {
		slog.Error("xiezhi-server exited", "err", err)
		os.Exit(1)
	}
}

func run() error {
	token := os.Getenv("XIEZHI_TOKEN")
	chDSN := os.Getenv("XIEZHI_CH_DSN")
	if token == "" {
		return errors.New("XIEZHI_TOKEN is required")
	}
	if chDSN == "" {
		return errors.New("XIEZHI_CH_DSN is required (clickhouse://user:pass@host:19000/xiezhi)")
	}
	listenAddr := getenv("XIEZHI_LISTEN", ":10580")
	httpAddr := getenv("XIEZHI_HTTP", ":10581")
	natsURL := getenv("XIEZHI_NATS_URL", "nats://127.0.0.1:4222")

	tlsCfg, err := tlsConfigFromEnv()
	if err != nil {
		return err
	}
	deadmanThreshold, err := secondsEnv("XIEZHI_DEADMAN_THRESHOLD_SEC", 180)
	if err != nil {
		return err
	}
	deadmanInterval, err := secondsEnv("XIEZHI_DEADMAN_INTERVAL_SEC", 30)
	if err != nil {
		return err
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()

	ch, err := store.OpenCH(ctx, chDSN)
	if err != nil {
		return err
	}
	defer ch.Close()

	batcher := store.NewBatcher(ch, queueSize, batchMaxRows, batchFlush)
	batcher.Start()

	nc, err := sink.ConnectNats(natsURL)
	if err != nil {
		batcher.Close()
		return fmt.Errorf("connect nats %s: %w", natsURL, err)
	}
	defer nc.Drain()

	dual := sink.NewDualWrite(nc, natsSubject, batcher)

	// M3 检测链：alerts 出口（CH + NATS）→ 规则引擎 → first-seen → session。
	// 任何一环装配失败只降级该环（大声说），不拒启动——采集与落库是底线。
	// 例外（R8.4 R-3）：XIEZHI_RULES_REQUIRE_SIGNATURE=1 生产态下规则/intent
	// 引擎装配失败是验签失败/篡改路径，fail-fast 拒启动。
	var handlers []pipeline.Handler
	var alertSink pipeline.Sink
	alertCh := store.NewAlertSink(ch)
	if err := ch.EnsureAlertsTable(ctx); err != nil {
		slog.Error("alerts table ensure failed, alerts persistence degraded", "err", err)
	}
	alertSink = (&store.NATSAlertPublisher{Publish: nc.Publish}).Wrap(alertCh)

	eng := (*rules.Engine)(nil) // 控制台 /api/rules /api/stats 依赖
	if dir := os.Getenv("XIEZHI_RULES_DIR"); dir != "" {
		if e, err := rules.New(dir, alertSink); err != nil {
			// R8.4 R-3：生产态规则引擎缺位而 healthz 照常 200 是「绿灯下的
			// 检测黑洞」——fail-fast 退出，撞钟语义交 systemd Restart=always。
			if rules.RequireSignedRules() {
				slog.Error("rules engine init failed in signed mode, exiting", "dir", dir, "err", err)
				os.Exit(1)
			}
			slog.Error("rules engine init failed, field rules disabled", "dir", dir, "err", err)
		} else {
			eng = e
			handlers = append(handlers, eng)
		}
	} else {
		slog.Warn("XIEZHI_RULES_DIR empty, field rules disabled")
	}

	fsHandler := (*firstseen.Handler)(nil)
	ssHandler := (*session.Handler)(nil)
	var treeDrill func(ctx context.Context, tsMs int64, ruleID, agentID string) (any, error) // 溯源图一期（PG 块内注入）
	var llmUsage func(ctx context.Context) (map[string]uint64, error)                        // 成本卡（triStore 块内注入）
	if dsn := os.Getenv("XIEZHI_PG_DSN"); dsn != "" {
		if fsStore, err := fspg.Open(dsn); err != nil {
			slog.Error("firstseen pg open failed, first-seen disabled", "err", err)
		} else {
			defer fsStore.Close()
			fsHandler = firstseen.New(fsStore, alertSink, firstseen.Config{})
			handlers = append(handlers, fsHandler)
		}
		if ssStore, err := sspg.Open(dsn); err != nil {
			slog.Error("session pg open failed, session aggregation disabled", "err", err)
		} else {
			defer ssStore.Close()
			var parent session.ParentExeRegistrar
			if fsHandler != nil {
				parent = fsHandler
			}
			ssHandler = session.New(ssStore, parent, session.Config{})
			handlers = append(handlers, ssHandler)
			// 溯源图一期（告警钻取）：event_ref 取进程复合键 → PG 归档树。
			// 实时树只在内存，归档滞后 10min idle 窗——SOC 复核场景可接受。
			ssq := ssStore
			treeDrill = func(ctx context.Context, tsMs int64, ruleID, agentID string) (any, error) {
				ref, err := ch.EventRefByAlert(ctx, tsMs, ruleID, agentID)
				if err != nil {
					return nil, err
				}
				// protojson 固定形态：uint64 字段字符串化（startTicks），
				// uint32 保持数字（pid）——两侧类型按此精确接收。
				var ev struct {
					Execve struct {
						Proc struct {
							Pid        int32  `json:"pid"`
							StartTicks string `json:"startTicks"`
						} `json:"proc"`
					} `json:"execve"`
				}
				if jerr := json.Unmarshal([]byte(ref), &ev); jerr != nil || ev.Execve.Proc.Pid == 0 {
					return map[string]any{"found": false, "reason": "event_ref missing or truncated"}, nil
				}
				ticks, terr := strconv.ParseUint(ev.Execve.Proc.StartTicks, 10, 64)
				if terr != nil {
					return map[string]any{"found": false, "reason": "event_ref proc keys unparsable"}, nil
				}
				// 验收发现（R9 浏览器面）：/alerts 列表不带 event_ref（4KB/行
				// 太重），抽屉侧 pid 提取恒 0——触发 pid 随树响应下发。
				treePid := ev.Execve.Proc.Pid
				tr, nodes, qerr := ssq.QueryTreeByProc(ctx, ev.Execve.Proc.Pid, ticks)
				if qerr != nil {
					return nil, qerr
				}
				if tr == nil {
					return map[string]any{"found": false, "reason": "session tree not archived yet (10min idle window)"}, nil
				}
				out := map[string]any{
					"found": true, "trigger_pid": treePid,
					"tree": map[string]any{
						"host": tr.Host, "root_pid": tr.RootPid,
						"first_ts_ms": tr.FirstTsMs, "last_ts_ms": tr.LastTsMs,
						"node_count": tr.NodeCount, "exes": tr.Exes,
					},
					"nodes": []map[string]any{},
				}
				ns := out["nodes"].([]map[string]any)
				for _, n := range nodes {
					ns = append(ns, map[string]any{
						"pid": n.Pid, "parent_pid": n.ParentPid, "exe": n.Exe,
						"argv": n.Argv, "first_ts_ms": n.FirstTsMs,
						"last_ts_ms": n.LastTsMs, "exited": n.Exited,
					})
				}
				out["nodes"] = ns
				return out, nil
			}
		}
	} else {
		slog.Warn("XIEZHI_PG_DSN empty, first-seen/session disabled")
	}

	// 意图层（M4）：策略文件缺=整层旁路（标签层可整体旁路）。
	intentStats := func() any { return nil } // 控制台 /api/stats 依赖
	if policyPath := os.Getenv("XIEZHI_INTENT_POLICY"); policyPath != "" {
		labeler, lerr := intent.NewLabelerFromEnv()
		if lerr != nil {
			slog.Error("intent labeler init failed, intent disabled", "err", lerr)
		} else {
			// R4.3：session 层可用时把桶键升级为会话树根 (host, rootPid)。
			var intentOpts []intent.Option
			if ssHandler != nil {
				intentOpts = append(intentOpts, intent.WithRootFinder(rootFinderAdapter{rf: ssHandler.RootFinder()}))
			}
			if ih, ierr := intent.New(labeler, alertSink, policyPath, intentOpts...); ierr != nil {
				// R8.4 R-3：intent.New 的 err 即 loadPolicy 启动期失败（含
				// 签名目录验签不过），生产态 fail-fast 同 rules 引擎；dev 降级。
				if rules.RequireSignedRules() {
					slog.Error("intent policy load failed in signed mode, exiting", "policy", policyPath, "err", ierr)
					os.Exit(1)
				}
				slog.Error("intent policy load failed, intent disabled", "err", ierr)
			} else {
				ihh := ih
				intentStats = func() any { return ihh.Stats() }
				handlers = append(handlers, ihh)
			}
		}
	} else {
		slog.Warn("XIEZHI_INTENT_POLICY empty, intent layer disabled")
	}

	pipe := pipeline.New(handlers...)

	// 先起 HTTP 再起 gRPC：依赖就绪探针先可用。
	// beats 提前创建：控制台 /api/agents /api/stats 与 ingest/deadman 共用。
	beats := ingest.NewHeartbeats()
	triageMux := http.NewServeMux()
	var consoleAuth *httpapi.AuthManager
	if pw := os.Getenv("XIEZHI_CONSOLE_PASSWORD"); pw != "" {
		consoleAuth = httpapi.NewAuthManager(pw)
		slog.Info("console auth enabled")
		// 30 分钟清理过期 session
		go func() {
			t := time.NewTicker(30 * time.Minute)
			defer t.Stop()
			for range t.C {
				consoleAuth.Cleanup()
			}
		}()
	} else {
		slog.Warn("XIEZHI_CONSOLE_PASSWORD empty, console auth disabled (dev mode)")
	}
	// 控制台专用端点：挂在与 /events /alerts 同一 mux，同等鉴权。
	httpapi.RegisterConsoleAPI(triageMux, httpapi.ConsoleDeps{
		Beats:         beats,
		BeatThreshold: deadmanThreshold,
		// Arch-1：typed-nil 装进接口后 != nil，降级分支不触发、
		// RuleSnapshot/Stats 必 panic——eng 为 nil 时显式传 nil 接口。
		Rules: func() interface {
			RuleSnapshot() []rules.RuleInfo
			Stats() rules.Stats
		} {
			if eng == nil {
				return nil
			}
			return eng
		}(),
		IntentStats: intentStats,
		Counts:      ch,
		TreeDrill:   treeDrill,
		// 闭包包装：triStore 在此后才构造（367 行区），直接传 llmUsage
		// 会拷走当时的 nil（函数值传递，非引用）——首轮部署实测踩中。
		LLMUsage: func(ctx context.Context) (map[string]uint64, error) {
			if llmUsage == nil {
				return nil, fmt.Errorf("llm usage not ready")
			}
			return llmUsage(ctx)
		},
	})
	// SSE 实时推送（R6.4）：AlertSink 入口即时广播到 /api/stream 订阅者。
	alertHub := httpapi.NewAlertHub()
	alertCh.SetBroadcast(alertHub.Broadcast)
	httpapi.RegisterStreamAPI(triageMux, alertHub)
	httpHandler := httpapi.NewWithAuth(ch, ch, triageMux, consoleAuth)
	// /triage 由 llm worker 挂载（见下）
	hs := &http.Server{Addr: httpAddr, Handler: httpHandler}
	serveErr := make(chan error, 2)
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("http serve: %w", err)
		}
	}()

	// degraded 外部出口（R8.5）：5min 巡检静默判据（与 /api/stats 同源），
	// 状态翻转时 POST XIEZHI_WEBHOOK_URL（未配则只 WARN 日志）。
	go func() {
		hook := strings.TrimSpace(os.Getenv("XIEZHI_WEBHOOK_URL"))
		wasDegraded := false
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			engines := map[string]any{}
			if eng != nil {
				engines["rules"] = eng.Stats()
			}
			if intentStats != nil {
				engines["intent"] = intentStats()
			}
			reasons := httpapi.DegradedReasons(engines)
			degraded := len(reasons) > 0
			if degraded == wasDegraded {
				continue
			}
			wasDegraded = degraded
			if !degraded {
				slog.Info("degraded cleared")
				continue
			}
			body, _ := json.Marshal(map[string]any{
				"text":    "xiezhi degraded: " + strings.Join(reasons, "; "),
				"reasons": reasons, "host": hostname(),
			})
			if hook != "" {
				resp, err := http.Post(hook, "application/json", bytes.NewReader(body))
				if err != nil {
					slog.Warn("degraded webhook post failed", "err", err)
				} else {
					resp.Body.Close()
					slog.Warn("degraded webhook sent", "status", resp.StatusCode, "reasons", reasons)
				}
			} else {
				slog.Warn("degraded detected, no XIEZHI_WEBHOOK_URL configured", "reasons", reasons)
			}
		}
	}()

	// 心跳持久化（M4）：同步回灌后才起看门狗——server 重启盲窗消除。
	// 失败降级运行（只丢持久化，看门狗照跑）。
	stopPersist := func() {}
	if dsn := os.Getenv("XIEZHI_PG_DSN"); dsn != "" {
		if stop, err := deadman.AttachPersist(beats, dsn, 30*time.Second); err != nil {
			slog.Error("heartbeat persist disabled", "err", err)
		} else {
			stopPersist = stop
		}
	}
	defer func() { stopPersist() }()

	gsOpts := []grpc.ServerOption{grpc.StreamInterceptor(auth.StreamInterceptor(token))}
	if tlsCfg != nil {
		gsOpts = append(gsOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	gs := grpc.NewServer(gsOpts...)
	ing := ingest.NewServer(dual, beats, buildVersion, windowCap)
	ing.SetPipeline(pipe)
	pb.RegisterIngestServer(gs, ing)

	recon := deadman.NewSASReconciler(
		os.Getenv("XIEZHI_SAS_AK"), os.Getenv("XIEZHI_SAS_SK"), os.Getenv("XIEZHI_SAS_ENDPOINT"))
	watchdog := deadman.New(beats, dual, recon, deadmanThreshold, deadmanInterval)
	// 独立于信号 ctx 的 cancel：serve 出错路径（ctx 未 Done）也要能停看门狗
	watchdogCtx, stopWatchdog := context.WithCancel(ctx)
	defer stopWatchdog()
	watchdogDone := make(chan struct{})
	go func() { watchdog.Run(watchdogCtx); close(watchdogDone) }()
	sasMode := "disabled"
	if os.Getenv("XIEZHI_SAS_AK") != "" && os.Getenv("XIEZHI_SAS_SK") != "" {
		sasMode = getenv("XIEZHI_SAS_ENDPOINT", "sas.cn-shanghai.aliyuncs.com")
	}

	// LLM shadow 研判（M4）：默认 mock provider 全链路可跑；真 GLM 换 env。
	// shadow 语义：只消费告警副本产三态，不触碰告警流本身。
	triStore := llm.NewCHStore(ch.Conn())
	if err := triStore.EnsureTable(context.Background()); err != nil {
		slog.Error("llm triage table ensure failed, shadow disabled", "err", err)
		triStore = nil
	} else {
		ts := triStore
		llmUsage = ts.Usage24h
	}
	if triStore != nil {
		cfg, cfgErr := llm.ConfigFromEnv()
		if cfgErr != nil {
			slog.Error("llm config invalid, shadow disabled", "err", cfgErr)
		} else {
			fetcher := &chEventFetcher{ch: ch}
			// 进程树证据源：session 层可用时必须用真树——此前注入的 nop
			// 空实现使 process_tree 证据段恒空，是 LLM 研判 insufficient
			// 占 89.5% 的最大单一原因。
			var subtree llm.SubtreeSource = &nopSubtreeSource{}
			if ssHandler != nil {
				subtree = ssHandler
			}
			w := llm.NewWorker(cfg, llm.NewProvider(cfg), triStore, fetcher, subtree)
			if err := w.Subscribe(nc); err != nil {
				slog.Error("llm worker subscribe failed, shadow disabled", "err", err)
			} else {
				defer w.Close()
				triageMux.Handle("/triage", llm.TriageHandler(triStore, w))
				slog.Info("llm shadow triage enabled",
					"provider", cfg.Provider, "model", cfg.Model)
			}
		}
	}

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	go func() {
		if err := gs.Serve(lis); err != nil {
			serveErr <- fmt.Errorf("grpc serve: %w", err)
		}
	}()
	slog.Info("xiezhi-server up", "version", buildVersion, "grpc", listenAddr, "http", httpAddr, "nats", natsURL,
		"mtls", tlsCfg != nil, "deadman_threshold", deadmanThreshold.String(),
		"deadman_interval", deadmanInterval.String(), "sas_reconcile", sasMode,
		"rules_dir", getenv("XIEZHI_RULES_DIR", ""), "pg", os.Getenv("XIEZHI_PG_DSN") != "")

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		slog.Error("serve failed, shutting down", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	hs.Shutdown(shutdownCtx)
	cancel()
	// agent 的流是长连接：GracefulStop 会一直等它们半关闭，超时后强停兜底
	stopped := make(chan struct{})
	go func() { gs.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		gs.Stop()
	}
	// 看门狗先于 batcher 停：否则退出瞬间的 AGENT_OFFLINE 会写进
	// 已排干的批量队列而静默丢失。检测链再后停（排干自身队列后出告警）。
	stopWatchdog()
	<-watchdogDone
	pipe.Close()
	alertCh.Close()
	batcher.Close()
	slog.Info("xiezhi-server down",
		"dropped", batcher.Dropped(), "flush_failed", batcher.FlushFailed())
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// tlsConfigFromEnv 装配 mTLS：XIEZHI_TLS_CA 空 = 灰度开关关闭，维持明文+token
// 现状；非空则要求证书三件套齐全且可加载，任何缺失/损坏 fail-fast 拒绝启动
// （半开 TLS 比明文更危险：会营造已加密的假象）。证书文件变更不热更，
// 重启生效——agent 侧长连接按重连节奏自然换发。
func tlsConfigFromEnv() (*tls.Config, error) {
	caPath := os.Getenv("XIEZHI_TLS_CA")
	if caPath == "" {
		return nil, nil
	}
	certPath := os.Getenv("XIEZHI_TLS_CERT")
	keyPath := os.Getenv("XIEZHI_TLS_KEY")
	if certPath == "" || keyPath == "" {
		return nil, errors.New("XIEZHI_TLS_CA set but XIEZHI_TLS_CERT/XIEZHI_TLS_KEY missing")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read tls ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificate parsed from %s", caPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// require AND verify：ClientCAs 非 nil + RequireAndVerifyClientCert，
		// 客户端证书由指定 CA 签发且必须出示
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// secondsEnv 解析「秒数」env：空用默认，非正数/非整数 fail-fast。
func secondsEnv(key string, def int) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return time.Duration(def) * time.Second, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer (got %q)", key, v)
	}
	return time.Duration(n) * time.Second, nil
}
