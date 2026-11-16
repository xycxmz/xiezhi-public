// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// GRPCSender 经 Ingest.Stream 客户端流上报。认证两层：mTLS（三路径齐则启用，
// M2 起）+ metadata `x-xiezhi-token`（纵深防御保留）。每批一个 RPC，accepted 按批可见。
type GRPCSender struct {
	addr    string
	token   string
	tlsCa   string
	tlsCert string
	tlsKey  string

	mu     sync.Mutex
	conn   *grpc.ClientConn
	client pb.IngestClient
}

// NewGRPCSender 构造 sender。tls 三路径任一非空即要求三路径齐备并启用 mTLS
//（部分配置是部署错误，fail-fast 优于静默降级明文）。
func NewGRPCSender(addr, token, tlsCa, tlsCert, tlsKey string) *GRPCSender {
	return &GRPCSender{addr: addr, token: token, tlsCa: tlsCa, tlsCert: tlsCert, tlsKey: tlsKey}
}

func (s *GRPCSender) SendBatch(ctx context.Context, batch *pb.EventBatch) (uint64, error) {
	if err := s.init(); err != nil {
		return 0, err
	}
	// 单次尝试限时：连接黑洞不能吃掉停机冲刷窗口。
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-xiezhi-token", s.token)
	stream, err := s.client.Stream(ctx)
	if err != nil {
		return 0, err
	}
	if err := stream.Send(batch); err != nil {
		return 0, err
	}
	summary, err := stream.CloseAndRecv()
	if err != nil {
		return 0, err
	}
	return summary.GetAccepted(), nil
}

func (s *GRPCSender) transportCredentials() (grpc.DialOption, error) {
	if s.tlsCa == "" && s.tlsCert == "" && s.tlsKey == "" {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	if s.tlsCa == "" || s.tlsCert == "" || s.tlsKey == "" {
		return nil, fmt.Errorf("tls config partial: need all of tls_ca/tls_cert/tls_key")
	}
	cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPEM, err := os.ReadFile(s.tlsCa)
	if err != nil {
		return nil, fmt.Errorf("read tls_ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("tls_ca: no valid certificates")
	}
	// ServerName 用证书 CN（xiezhi-server）；IP 直连场景不校验域名
	return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "xiezhi-server",
	})), nil
}

func (s *GRPCSender) init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return nil
	}
	dialOpt, err := s.transportCredentials()
	if err != nil {
		return err
	}
	// NewClient 惰性连接并自带重连；RPC 默认 fail-fast，失败即时返回
	// 交由外层 backoff 控节奏。证书变更重启生效（不热更，防半态）。
	conn, err := grpc.NewClient(s.addr, dialOpt)
	if err != nil {
		return err
	}
	s.conn = conn
	s.client = pb.NewIngestClient(conn)
	return nil
}

func (s *GRPCSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	s.client = nil
	return err
}
