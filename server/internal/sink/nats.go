// SPDX-License-Identifier: Apache-2.0

package sink

import "github.com/nats-io/nats.go"

// ConnectNats 建立普通 core NATS 连接（M1 用 pub/sub，JetStream 属后续里程碑）。
func ConnectNats(url string) (*nats.Conn, error) {
	return nats.Connect(url)
}
