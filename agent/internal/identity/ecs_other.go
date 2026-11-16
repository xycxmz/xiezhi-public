// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package identity

// 非 Linux 开发机：无 metadata 通道。
func ecsInstanceID() string { return "" }
