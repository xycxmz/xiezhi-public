// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeStream 只会被读 Context()：拦截器在放行前后不触及其余方法，
// 嵌入的 nil 接口因此安全。
type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeStream) Context() context.Context { return f.ctx }

// Append 而非 Set：Set 是替换语义，无法构造出多值头的真实形态
func withToken(tokens ...string) context.Context {
	md := metadata.MD{}
	for _, t := range tokens {
		md.Append(TokenHeader, t)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestStreamInterceptorRejects(t *testing.T) {
	ic := StreamInterceptor("secret-token")
	cases := []struct {
		name string
		ctx  context.Context
	}{
		{"no metadata", context.Background()},
		{"no token header", metadata.NewIncomingContext(context.Background(), metadata.MD{})},
		{"wrong token", withToken("wrong")},
		{"duplicate tokens", withToken("secret-token", "secret-token")},
		{"empty token value", withToken("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			err := ic(nil, fakeStream{ctx: tc.ctx}, &grpc.StreamServerInfo{},
				func(any, grpc.ServerStream) error { called = true; return nil })
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
			}
			if called {
				t.Fatal("handler must not run on auth failure")
			}
		})
	}
}

func TestStreamInterceptorAccepts(t *testing.T) {
	sentinel := errors.New("handler ran")
	ic := StreamInterceptor("secret-token")
	err := ic(nil, fakeStream{ctx: withToken("secret-token")}, &grpc.StreamServerInfo{},
		func(any, grpc.ServerStream) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("handler result not propagated: %v", err)
	}
}

func TestStreamInterceptorEmptyExpectedTokenRejectsAll(t *testing.T) {
	ic := StreamInterceptor("")
	err := ic(nil, fakeStream{ctx: withToken("")}, &grpc.StreamServerInfo{}, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}
