// SPDX-License-Identifier: Apache-2.0

// Package deadman 实现服务器侧 dead-man 看门狗：心跳缺失 × 云电源对账
// → AGENT_OFFLINE 事件。存在理由：实测中 clientStatus=offline 的机器
// 大多是正常关机机，不对账直接告警则全是误报。
package deadman

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"golang.org/x/sync/errgroup"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// 对账全量拉的硬上限：千台级车队 / PageSize 100 要几十页，60 页留余量，
// 防 SAS 端分页异常时死循环。
const (
	sasPageSize    = 100
	sasMaxPages    = 60
	sasFetchBudget = 30 * time.Second // 对账超时放弃本次，用旧缓存或 not_found；4 路并发下千台级约十余秒
	cacheTTL       = 5 * time.Minute  // instance→状态缓存，避免每告警全量拉
)

// sasInstance 是 DescribeCloudCenterInstances 返回的主机类资产投影
// （字段 PascalCase）。
type sasInstance struct {
	InstanceID   string `json:"InstanceId"`
	Uuid         string `json:"Uuid"`
	ClientStatus string `json:"ClientStatus"`
	Status       string `json:"Status"`
	OsName       string `json:"OsName"`
}

// instanceSource 抽象全量拉取，真实现为 SAS RPC 客户端，测试为 fake。
type instanceSource interface {
	fetchAll(ctx context.Context) ([]sasInstance, error)
}

// sasClient 走阿里云 RPC 签名（HMAC-SHA1 GET，Version 2018-12-03）。
// nonce/now 可注入以使签名可测。
type sasClient struct {
	ak       string
	sk       string
	endpoint string
	http     *http.Client
	nonce    func() string
	now      func() time.Time
}

func newSASClient(ak, sk, endpoint string) *sasClient {
	return &sasClient{
		ak: ak, sk: sk, endpoint: endpoint,
		http:  &http.Client{Timeout: sasFetchBudget},
		nonce: func() string { return uuid.NewString() },
		now:   time.Now,
	}
}

func (c *sasClient) fetchAll(ctx context.Context) ([]sasInstance, error) {
	// 首页串行拿 TotalCount，余页 4 路并发：千台级车队要几十页，
	// 串行塞不进对账预算（实测 ~1s/页 → 首版 reconcile_unavailable 的根因）
	fetchPage := func(page int) ([]sasInstance, int, error) {
		var out struct {
			Instances json.RawMessage `json:"Instances"`
			PageInfo  struct {
				Total int `json:"Total"`
			} `json:"PageInfo"`
		}
		if err := c.call(ctx, map[string]string{
			"PageSize":    fmt.Sprint(sasPageSize),
			"CurrentPage": fmt.Sprint(page),
		}, &out); err != nil {
			return nil, 0, err
		}
		insts, err := decodeInstances(out.Instances)
		return insts, out.PageInfo.Total, err
	}

	first, total, err := fetchPage(1)
	if err != nil {
		return nil, err
	}
	if len(first) < sasPageSize || (total > 0 && total <= sasPageSize) {
		return first, nil
	}
	pages := (total + sasPageSize - 1) / sasPageSize
	if total == 0 || pages > sasMaxPages {
		pages = sasMaxPages // Total 缺失时按空页判据收敛
	}

	results := make([][]sasInstance, pages+1)
	results[1] = first
	var g errgroup.Group
	sem := make(chan struct{}, 4)
	for page := 2; page <= pages; page++ {
		page := page
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			insts, _, err := fetchPage(page)
			if err != nil {
				return err
			}
			results[page] = insts
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	all := make([]sasInstance, 0, pages*sasPageSize)
	for page := 1; page <= pages; page++ {
		// 分页判据=返回空页；Total 只做日志参考
		if len(results[page]) == 0 {
			break
		}
		all = append(all, results[page]...)
	}
	return all, nil
}

// SAS 响应坑：Instances 直接是数组，但保留对
// {"Instance": [...]} 包装形态的兼容，两种都见过。
func decodeInstances(raw json.RawMessage) ([]sasInstance, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var arr []sasInstance
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var wrapped struct {
		Instance []sasInstance `json:"Instance"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("instances payload: %w", err)
	}
	return wrapped.Instance, nil
}

func (c *sasClient) call(ctx context.Context, extra map[string]string, out any) error {
	params := map[string]string{
		"AccessKeyId":      c.ak,
		"Action":           "DescribeCloudCenterInstances",
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   c.nonce(),
		"SignatureVersion": "1.0",
		"Timestamp":        c.now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2018-12-03",
	}
	for k, v := range extra {
		params[k] = v
	}
	sig := signRPC(params, c.sk)
	params["Signature"] = sig

	endpoint := c.endpoint
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	reqURL := endpoint + "/?" + encodeParams(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sas http %d: %.200s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("sas decode: %w", err)
	}
	return nil
}

// signRPC 计算阿里云 RPC 签名：base64(hmac-sha1(SK+"&", "GET&%2F&"+pe(sorted query)))。
// params 不得含 Signature 键（调用方在签名后追加）。
func signRPC(params map[string]string, sk string) string {
	sts := "GET&%2F&" + percentEncode(encodeParams(params))
	mac := hmac.New(sha1.New, []byte(sk+"&"))
	mac.Write([]byte(sts))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// encodeParams 输出按 key 字典序的 canonical query（签名与请求 URL 共用）。
func encodeParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

// percentEncode 按 RFC3986：空格=%20、*=%2A、~=~（阿里云规则，非 form 编码）。
func percentEncode(s string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(s))
}

// classifyPower 把 SAS 实例状态归一为电源态。判定（契约）：
//   - running                       → running   （告警侧）
//   - notRunning                    → stopped   （关机机，抑制）
//   - UNKNOWN/空 且 ClientStatus=offline → stopped（关机机，抑制）
//   - 其余（UNKNOWN 但 aegis 报 online、未见过的状态值）→ unknown（告警侧）
//
// dead-man 的偏好是「云侧没有明确说关机就告警」：过度抑制会吞掉
// 「开机但 agent 被杀」这一真实攻击面。
func classifyPower(status, clientStatus string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return powerRunning
	case "notrunning":
		return powerStopped
	default:
		if strings.EqualFold(strings.TrimSpace(clientStatus), "offline") {
			return powerStopped
		}
		return powerUnknown
	}
}

const (
	powerRunning  = "running"
	powerStopped  = "stopped"
	powerNotFound = "not_found"
	powerUnknown  = "unknown"
)

// Reconciler 是带 TTL 缓存的电源对账器：Uuid 与 InstanceId 双键索引，
// 按 agent_id 匹配（M2 匹配面=agent_id 恰为二者之一；不匹配即 not_found）。
// 无凭据（src=nil）时一律 not_found——契约允许的「不对账」形态，宁可告警。
type Reconciler struct {
	src instanceSource
	ttl time.Duration
	now func() time.Time

	mu        sync.Mutex
	byAgentID map[string]string
	fetchedAt time.Time
	fetchOK   bool
}

func NewReconciler(src instanceSource) *Reconciler {
	return &Reconciler{src: src, ttl: cacheTTL, now: time.Now}
}

// NewSASReconciler 是 main 的装配入口：AK/SK 任一为空即不对账（nil 数据源，
// 一律 not_found），endpoint 默认区域 POP（中心域名实测超时）。
func NewSASReconciler(ak, sk, endpoint string) *Reconciler {
	if ak == "" || sk == "" {
		return NewReconciler(nil)
	}
	if endpoint == "" {
		endpoint = "sas.cn-shanghai.aliyuncs.com"
	}
	return NewReconciler(newSASClient(ak, sk, endpoint))
}

// State 返回 agent 的电源态与缓存健康度。staleCache=true 表示答案来自
// 过期缓存（本次刷新失败），调用方应把它写进事件 Detail 供运维识别。
func (r *Reconciler) State(ctx context.Context, agentID string) (state string, staleCache bool) {
	if r.src == nil {
		return powerNotFound, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.now().Sub(r.fetchedAt) > r.ttl {
		r.refreshLocked(ctx)
	}
	state, ok := r.byAgentID[agentID]
	if !ok {
		return powerNotFound, !r.fetchOK
	}
	return state, !r.fetchOK
}

// refreshLocked 全量拉一次并重建索引；失败保留旧缓存内容且也推进 fetchedAt
// （占用一个 TTL 窗口的失败退避）：SAS 不可达（黑洞超时）时看门狗单轮扫描只
// 烧一次 sasFetchBudget 预算，TTL 后再重试——否则每个 stale agent 的 State
// 都各重试一次 30s 全量拉取，一轮扫描被拖到 N×30s，看门狗停摆。
func (r *Reconciler) refreshLocked(ctx context.Context) {
	if r.src == nil {
		return
	}
	fetchCtx, cancel := context.WithTimeout(ctx, sasFetchBudget)
	defer cancel()
	insts, err := r.src.fetchAll(fetchCtx)
	if err != nil {
		r.fetchOK = false
		r.fetchedAt = r.now()
		return
	}
	idx := make(map[string]string, len(insts)*2)
	for _, it := range insts {
		st := classifyPower(it.Status, it.ClientStatus)
		if it.Uuid != "" {
			idx[it.Uuid] = st
		}
		if it.InstanceID != "" {
			idx[it.InstanceID] = st
		}
	}
	r.byAgentID = idx
	r.fetchedAt = r.now()
	r.fetchOK = true
}
