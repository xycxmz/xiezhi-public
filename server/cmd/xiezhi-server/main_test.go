// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCertChain 生成自签 CA + 由 CA 签发的 server/client 叶证书，落盘临时目录。
type testCerts struct {
	dir        string
	caPath     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
	caPool     *x509.CertPool
}

func writeCertChain(t *testing.T) testCerts {
	t.Helper()
	dir := t.TempDir()
	tc := testCerts{dir: dir, caPath: filepath.Join(dir, "ca.pem"),
		serverCert: filepath.Join(dir, "server.pem"), serverKey: filepath.Join(dir, "server.key.pem"),
		clientCert: filepath.Join(dir, "client.pem"), clientKey: filepath.Join(dir, "client.key.pem")}

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xiezhi-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tc.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	tc.caPool = x509.NewCertPool()
	tc.caPool.AddCert(caCert)

	leaf := func(cn string, server bool) (string, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{cn},
		}
		if server {
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPath := filepath.Join(dir, cn+".pem")
		keyPath := filepath.Join(dir, cn+".key.pem")
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
			t.Fatal(err)
		}
		return certPath, keyPath
	}
	tc.serverCert, tc.serverKey = leaf("server", true)
	tc.clientCert, tc.clientKey = leaf("client", false)
	return tc
}

func TestTLSConfigFromEnvMatrix(t *testing.T) {
	tc := writeCertChain(t)

	t.Run("empty env keeps plaintext+token status quo", func(t *testing.T) {
		cfg, err := tlsConfigFromEnv()
		if cfg != nil || err != nil {
			t.Fatalf("cfg=%v err=%v, want nil/nil", cfg, err)
		}
	})

	t.Run("ca set but cert/key missing fails fast", func(t *testing.T) {
		t.Setenv("XIEZHI_TLS_CA", tc.caPath)
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Fatal("want error when cert/key missing")
		}
		t.Setenv("XIEZHI_TLS_CERT", tc.serverCert)
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Fatal("want error when key missing")
		}
	})

	t.Run("corrupt ca pem fails fast", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XIEZHI_TLS_CA", bad)
		t.Setenv("XIEZHI_TLS_CERT", tc.serverCert)
		t.Setenv("XIEZHI_TLS_KEY", tc.serverKey)
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Fatal("want error on unparsable CA")
		}
	})

	t.Run("missing ca file fails fast", func(t *testing.T) {
		t.Setenv("XIEZHI_TLS_CA", filepath.Join(t.TempDir(), "absent.pem"))
		t.Setenv("XIEZHI_TLS_CERT", tc.serverCert)
		t.Setenv("XIEZHI_TLS_KEY", tc.serverKey)
		if _, err := tlsConfigFromEnv(); err == nil {
			t.Fatal("want error on absent CA file")
		}
	})

	t.Run("full set assembles require-and-verify mTLS", func(t *testing.T) {
		t.Setenv("XIEZHI_TLS_CA", tc.caPath)
		t.Setenv("XIEZHI_TLS_CERT", tc.serverCert)
		t.Setenv("XIEZHI_TLS_KEY", tc.serverKey)
		cfg, err := tlsConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
		}
		if cfg.ClientCAs == nil || len(cfg.ClientCAs.Subjects()) == 0 {
			t.Fatal("ClientCAs pool empty")
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("server certs = %d, want 1", len(cfg.Certificates))
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %x, want TLS1.2+", cfg.MinVersion)
		}
	})
}

// 真握手验证装配产物可用：带客户端证书成功，不带则被 RequireAndVerify 拒绝。
func TestTLSHandshakeWithAndWithoutClientCert(t *testing.T) {
	tc := writeCertChain(t)
	t.Setenv("XIEZHI_TLS_CA", tc.caPath)
	t.Setenv("XIEZHI_TLS_CERT", tc.serverCert)
	t.Setenv("XIEZHI_TLS_KEY", tc.serverKey)
	cfg, err := tlsConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener 关闭或被拒握手（certificate_required）即退出
			}
			go func() { // 服务端只读一条记录保证握手完成
				buf := make([]byte, 16)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
				c.Close()
			}()
		}
	}()
	defer func() { ln.Close(); <-done }()

	clientPair, err := tls.LoadX509KeyPair(tc.clientCert, tc.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(clientCfg *tls.Config) error {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", ln.Addr().String(), clientCfg)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		// TLS1.3 下客户端证书校验失败在握手飞行后以告警浮现：
		// 必须读到错误（certificate required）才算被拒；正常路径读到 EOF。
		if _, err := conn.Read(make([]byte, 16)); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	}

	withCert := &tls.Config{RootCAs: tc.caPool, Certificates: []tls.Certificate{clientPair},
		ServerName: "server", MinVersion: tls.VersionTLS12}
	if err := dial(withCert); err != nil {
		t.Fatalf("handshake with client cert failed: %v", err)
	}

	noCert := &tls.Config{RootCAs: tc.caPool, ServerName: "server", MinVersion: tls.VersionTLS12}
	if err := dial(noCert); err == nil {
		t.Fatal("handshake without client cert must be rejected")
	}
}

func TestSecondsEnv(t *testing.T) {
	cases := []struct {
		name, val string
		want      time.Duration
		wantErr   bool
	}{
		{"empty uses default", "", 180 * time.Second, false},
		{"valid", "45", 45 * time.Second, false},
		{"zero", "0", 0, true},
		{"negative", "-5", 0, true},
		{"garbage", "abc", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XIEZHI_DEADMAN_THRESHOLD_SEC", tc.val)
			got, err := secondsEnv("XIEZHI_DEADMAN_THRESHOLD_SEC", 180)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error for %q", tc.val)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v err=%v, want %v", got, err, tc.want)
			}
		})
	}
}
