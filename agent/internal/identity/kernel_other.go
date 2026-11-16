// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package identity

// 开发/测试平台（Windows/macOS）无 uname；Kernel 留空，仅影响事件头字段值。
func kernelRelease() string { return "" }
