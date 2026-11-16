// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/subtle"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenHeader 是 agent 与 server 约定的 gRPC metadata 认证键。
const TokenHeader = "x-xiezhi-token"

// StreamInterceptor 校验 x-xiezhi-token 与 expected 一致，失败返回 Unauthenticated。
// expected 为空一律拒绝（XIEZHI_TOKEN 缺失时宁可全拒不可裸奔）。
func StreamInterceptor(expected string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !tokenOK(ss.Context(), expected) {
			return status.Error(codes.Unauthenticated, "invalid or missing "+TokenHeader)
		}
		return handler(srv, ss)
	}
}

func tokenOK(ctx context.Context, expected string) bool {
	if expected == "" {
		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	vs := md.Get(TokenHeader)
	if len(vs) != 1 {
		return false
	}
	// 常数时间比较：token 是长期共享密钥，逐字节比较会泄露前缀匹配长度
	return subtle.ConstantTimeCompare([]byte(vs[0]), []byte(expected)) == 1
}
