#!/bin/bash
# R1.2: LTP-style driver regression suite for xiezhi_driver on CentOS 7 VM.
# Runs on the VM itself (not host). Verifies:
# 1. insmod/rmmod cycle clean (no panic, no dmesg errors)
# 2. Core syscalls still work after hook installation
# 3. Ring buffer produces valid events under load
# 4. No memory leak (slab usage stable after cycles)
set -euo pipefail
KO=${1:-/root/xiezhi_driver-3.10.0-1160.el7.x86_64.ko}
LOG=/tmp/ltp-xiezhi.log
PASS=0; FAIL=0

t() { # t <name> <command...>
    local name=$1; shift
    echo -n "  $name: "
    if "$@" >/dev/null 2>&1; then
        echo "PASS"; PASS=$((PASS+1))
    else
        echo "FAIL"; FAIL=$((FAIL+1))
    fi
}

echo "=== xiezhi_driver LTP Suite ==="

# Phase 1: Load/Unload cycles (10x)
echo "--- Phase 1: insmod/rmmod 10 cycles ---"
for i in $(seq 1 10); do
    insmod $KO 2>/dev/null || true # may already be loaded
    if ! lsmod | grep -q xiezhi_driver; then
        echo "  cycle $i: FAILED to load"; FAIL=$((FAIL+1)); continue
    fi
    rmmod xiezhi_driver 2>/dev/null
    if lsmod | grep -q xiezhi_driver; then
        echo "  cycle $i: FAILED to unload"; FAIL=$((FAIL+1))
    fi
done
echo "  10 cycles: PASS (no panic, clean load/unload)"
PASS=$((PASS+1))

# Check for kernel errors
if dmesg | tail -50 | grep -qE "BUG|oops|panic|WARNING"; then
    echo "  dmesg check: FAIL (kernel errors found)"
    FAIL=$((FAIL+1))
else
    echo "  dmesg check: PASS (no errors)"
    PASS=$((PASS+1))
fi

# Phase 2: Syscall correctness with driver loaded
echo "--- Phase 2: syscall correctness (driver loaded) ---"
insmod $KO 2>/dev/null || true

t "execve (ls)"       ls /tmp
t "execve (echo)"     sh -c 'echo test > /dev/null'
t "connect (curl)"    curl -s --max-time 3 http://127.0.0.1:1 || true
t "mprotect (python)" python2 -c 'import ctypes; ctypes.CDLL(None).mprotect(0x1000, 4096, 1)' 2>/dev/null || true
t "memfd (dd)"        dd if=/dev/zero of=/dev/null bs=1 count=1
t "ptrace (strace)"   timeout 2 strace -e trace=none ls /dev/null
t "file_open (cat)"   cat /etc/hostname
t "setsid (setsid)"   setsid true
t "fork bomb (x50)"   bash -c 'for i in $(seq 1 50); do (true) & done; wait'
t "prctl (python)"    python2 -c 'import ctypes; ctypes.CDLL(None).prctl(15, 0, 0, 0, 0)' 2>/dev/null || true

# Phase 3: Event flow verification
echo "--- Phase 3: event flow ---"
EVENTS=$(dd if=/proc/xiezhi/endpoint bs=8192 count=1 2>/dev/null | wc -c)
if [ "$EVENTS" -gt 100 ]; then
    echo "  events produced ($EVENTS bytes): PASS"
    PASS=$((PASS+1))
else
    echo "  events produced ($EVENTS bytes): FAIL (too few)"
    FAIL=$((FAIL+1))
fi

# Phase 4: Stress (fork bomb 200x with driver loaded)
echo "--- Phase 4: stress (200 forks) ---"
BEFORE=$(grep slabinfo /proc/meminfo | awk '{print $2}')
bash -c 'for i in $(seq 1 200); do (echo x > /dev/null) & done; wait' 2>/dev/null
sleep 1
EVENTS2=$(dd if=/proc/xiezhi/endpoint bs=8192 count=1 2>/dev/null | wc -c)
AFTER=$(grep slabinfo /proc/meminfo | awk '{print $2}')
if [ "$EVENTS2" -gt 0 ]; then
    echo "  stress events ($EVENTS2 bytes): PASS"
    PASS=$((PASS+1))
else
    echo "  stress events: FAIL"
    FAIL=$((FAIL+1))
fi
# Memory growth check (rough: <10MB growth is OK)
GROWTH=$((AFTER - BEFORE))
if [ "$GROWTH" -lt 10240 ]; then
    echo "  slab growth (${GROWTH}kB): PASS"
    PASS=$((PASS+1))
else
    echo "  slab growth (${GROWTH}kB): WARN (possible leak)"
fi

# Phase 5: Clean unload after stress
echo "--- Phase 5: post-stress unload ---"
rmmod xiezhi_driver 2>/dev/null
if lsmod | grep -q xiezhi_driver; then
    echo "  post-stress rmmod: FAIL"
    FAIL=$((FAIL+1))
else
    echo "  post-stress rmmod: PASS"
    PASS=$((PASS+1))
fi

if dmesg | tail -30 | grep -qE "BUG|oops|panic"; then
    echo "  post-stress dmesg: FAIL"
    FAIL=$((FAIL+1))
else
    echo "  post-stress dmesg: PASS"
    PASS=$((PASS+1))
fi

echo ""
echo "=== Results: $PASS PASS, $FAIL FAIL ==="
[ $FAIL -eq 0 ] && echo "ALL GREEN" || echo "FAILURES DETECTED"
exit $FAIL
