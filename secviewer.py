#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secviewer.py — 리눅스 침해사고 보안 로그 뷰어

SSH 침입 → 명령 실행 → DB 덤프 → 파일 전송(유출) 흐름을 여러 로그에서 모아
타임라인 / 공격자 IP / 세션 뷰가 있는 단일 HTML 리포트로 만든다.
Python 3.8+ 표준 라이브러리만 사용하므로 서버에 이 파일 하나만 올려 실행하면 된다.

  sudo python3 secviewer.py                         # 현재 서버(/) 분석 → secview_report.html
  python3 secviewer.py --root ./evidence            # 수집해 온 로그(/ 디렉터리 구조 그대로) 분석
  sudo python3 secviewer.py --serve 8080            # 분석 후 http://127.0.0.1:8080 으로 보기
  python3 secviewer.py --root ./evidence --json out.json   # JSON 으로도 저장

읽는 로그
  SSH/계정   /var/log/auth.log*, /var/log/secure*  (없으면 journalctl)
  명령       /var/log/audit/audit.log* (EXECVE), ~/.bash_history 등, sudo COMMAND
  로그인기록 /var/log/wtmp*, /var/log/btmp*
  DB         MySQL general log, PostgreSQL 로그
  파일전송   SFTP(internal-sftp, LogLevel VERBOSE), vsftpd/xferlog, scp/curl/wget/rsync 명령
"""
import argparse
import datetime as dt
import fnmatch
import glob
import gzip
import hashlib
import http.server
import ipaddress
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from collections import Counter, defaultdict

SEVS = ['info', 'low', 'med', 'high', 'crit']
SEV_RANK = {s: i for i, s in enumerate(SEVS)}
MONTHS = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}
UNSET_AUID = {'4294967295', '-1', 'unset'}
TZ_ABBR = {'UTC': 0, 'GMT': 0, 'KST': 540, 'JST': 540, 'CST': 480, 'CET': 60, 'CEST': 120,
           'EST': -300, 'EDT': -240, 'PST': -480, 'PDT': -420}

CATS = {
    'auth':         'SSH 인증',
    'session':      '세션',
    'cmd':          '명령어',
    'db':           'DB 접근·덤프',
    'transfer':     '파일 전송',
    'persist':      '지속성 확보',
    'antiforensic': '흔적 삭제',
    'exec':         '악성 실행',
    'privesc':      '권한 상승',
    'recon':        '정찰',
    'lateral':      '나간 접속',
    'fileop':       '파일 작업',
}

# ───────────────────────── 명령어 분류 규칙 ─────────────────────────
# 명령 위치(줄 처음, 파이프/세미콜론 뒤, sudo/nohup 뒤)에 나온 실행 파일만 잡는다.
_HEAD = r'(?:^|[;&|`(]\s*|\$\(\s*|\bsudo\s+(?:-\S+\s+(?:\w+\s+)?)*|\bnohup\s+|\btime\s+|\bexec\s+)(?:\S*/)?'


def _c(names):
    return _HEAD + r'(?:' + names + r')(?=\s|$|;|\||\))'


# (분류, 기본 위험도, 라벨, 정규식) — 위에서부터 우선순위
RULES = [(c, s, l, re.compile(p)) for c, s, l, p in [
    ('antiforensic', 'crit', '흔적 삭제',
     r'history\s+-[cw]|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|set\s+\+o\s+history|\bshred\b'
     r'|\brm\s+(?:-\S+\s+)*\S*(?:_history|/var/log/)|(?:^|[\s;])(?:>|cat\s+/dev/null\s*>)\s*/var/log/'
     r'|\btruncate\s.*(?:/var/log|_history)|journalctl\s.*--(?:vacuum|rotate)|\bauditctl\s+-D'
     r'|(?:service\s+auditd\s+stop|systemctl\s+stop\s+(?:auditd|rsyslog|syslog))|\btouch\s+-[a-z]*[rdt]\b'),
    ('exec', 'crit', '리버스 셸 의심',
     r'\b(?:ba|z)?sh\s+-i\b.*/dev/(?:tcp|udp)/|/dev/(?:tcp|udp)/\S+.*[0-2]>&[0-2]|\bnc(?:at)?\s(?:.*\s)?-[ec]\s'
     r'|\bmkfifo\b.*\bnc\b|\bsocat\b.*\bexec:|pty\.spawn|socket\.socket\(.*connect'),
    ('db', 'crit', 'DB 덤프',
     _c(r'mysqldump|mariadb-dump|mydumper|xtrabackup|mariabackup|pg_dump|pg_dumpall|pg_basebackup'
        r'|mongodump|mongoexport|expdp|exp')
     + r'|redis-cli\b.*(?:--rdb\b|\bbgsave\b|\bsave\b)|sqlite3\b.*\.(?:dump|backup)|(?i:into\s+(?:out|dump)file)'
       r'|(?i:\bcopy\b.+\bto\s+(?:\'|stdout|program))'
       r'|\b(?:cp|scp|rsync|tar)\b.*(?:/var/lib/(?:mysql|postgresql|pgsql|mongodb|redis)\b|\.(?:ibd|rdb|sqlite3?)\b)'),
    ('transfer', 'med', '파일 전송',
     _c(r'scp|sftp|rsync|wget|curl|ftp|lftp|tftp|nc|ncat|netcat|socat|rclone|smbclient|axel|aria2c|azcopy|gsutil')
     + r'|/dev/tcp/|\baws\s+s3\s+(?:cp|sync|mv)\b|python[23]?\s+-m\s+(?:http\.server|SimpleHTTPServer)|\bphp\s+-S\b'),
    ('persist', 'high', '지속성 확보',
     _c(r'useradd|adduser|usermod|chpasswd|visudo|passwd') + r'|' + _c(r'crontab') + r'(?!\s+-l\b)'
     r'|authorized_keys|/etc/(?:rc\.local|cron\S*|sudoers\S*|systemd/system/\S+|ld\.so\.preload|profile\.d/)'
     r'|systemctl\s+enable|>>?\s*\S*\.(?:bashrc|bash_profile|profile)\b'),
    ('exec', 'high', '악성 실행 의심',
     r'\b(?:ba)?sh\s+-i\b|/dev/(?:tcp|udp)/|python[23]?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|base64\s+(?:-d|--decode)'
     r'|\bchmod\s+(?:[ugoa]*\+x|0?7[0-7]{2})\b|\|\s*(?:ba|z)?sh\b|\bmkfifo\b|\bnohup\b|\bLD_PRELOAD='
     r'|(?:^|[;&|]\s*)\./\S+|(?:^|[;&|]\s*)/(?:tmp|dev/shm|var/tmp)/\S+|\bxmrig\b'),
    ('recon', 'high', '자격증명 탐색',
     r'(?:cat|less|more|head|tail|grep|strings|vi|vim|nano|cp|base64|xxd)\b.*(?:/etc/shadow|wp-config\.php|config\.php|\.env\b'
     r'|\.my\.cnf|\.pgpass|id_rsa|id_ed25519|credentials|\.aws/|database\.yml|settings\.py)'),
    ('lateral', 'high', 'SSH 터널', r'\bssh\b.*\s-[LRD]\s*\S'),
    ('lateral', 'med', '다른 서버로 접속', _c(r'ssh|telnet|mosh')),
    ('privesc', 'med', '권한 상승',
     _c(r'sudo|su|pkexec|doas') + r'|chmod\s+(?:[ugoa]*\+s|[2-7][0-7]{3})\b|\bsetcap\b'),
    ('db', 'med', 'DB 접속', _c(r'mysql|mariadb|psql|mongo|mongosh|redis-cli|sqlplus|sqlite3|clickhouse-client')),
    ('fileop', 'low', '파일 삭제', _c(r'rm|unlink|rmdir|shred')),
    ('fileop', 'low', '파일 이동·이름 변경', _c(r'mv')),
    ('fileop', 'low', '파일 복사', _c(r'cp|install|dd')),
    ('cmd', 'low', '압축·스테이징', _c(r'tar|zip|7z|7za|rar|gzip|bzip2|xz|split')),
    ('fileop', 'low', '파일 저장', r'(?:^|[^0-9&>])>>?\s*(?!/dev/null\b|&)[^\s;&|]+|\btee\s+(?:-a\s+)?[^\s;&|-]'),
    ('fileop', 'info', '파일 생성·폴더 생성', _c(r'touch|mkdir')),
    ('recon', 'low', '정찰',
     _c(r'whoami|id|uname|hostname|ifconfig|netstat|ss|ps|w|who|last|lastlog|lsof|env|arp|route|getent')
     + r'|cat\s+/etc/(?:passwd|group|hosts|issue|\S*release)|\bfind\s.*-perm\s+(?:[-/]?[246]000|-u=s)|\bip\s+(?:a|addr|r|route|neigh)\b|crontab\s+-l|sudo\s+-l'),
]]

_ARG_REMOTE = re.compile(r'^[^/\s]*:')  # host:path, user@host:path


def transfer_detail(cmd):
    """파일 전송 명령의 방향(유출/반입)을 구분해 (위험도, 설명)을 돌려준다."""
    if re.search(r'\bscp\b(?:\s+-\S+)*\s+-[A-Za-z]*f(?:\s|$)', cmd):
        return 'crit', 'scp 원격 다운로드 (서버 → 외부 유출)'
    if re.search(r'\bscp\b(?:\s+-\S+)*\s+-[A-Za-z]*t(?:\s|$)', cmd):
        return 'high', 'scp 원격 업로드 (외부 → 서버 반입)'
    if re.search(r'\bcurl\b.*(?:\s-T\s|--upload-file|\s-F\s|--form\b|--data(?:-binary)?\s+@|\s-d\s*@)', cmd):
        return 'crit', 'curl 업로드 (외부 유출)'
    if re.search(r'\b(?:rclone|azcopy|gsutil)\b|\baws\s+s3\s', cmd):
        return 'crit', '클라우드 스토리지 전송'
    for seg in re.split(r'[|;&]', cmd):
        toks = seg.split()
        idx = next((i for i, t in enumerate(toks) if re.search(r'(?:^|/)(?:scp|rsync)$', t)), None)
        if idx is None:
            continue
        args = [t for t in toks[idx + 1:] if not t.startswith('-')]
        if args and _ARG_REMOTE.match(args[-1]):
            return 'crit', '외부 서버로 전송 (유출)'
        if any(_ARG_REMOTE.match(a) for a in args[:-1]):
            return 'high', '외부 서버에서 반입'
    if re.search(r'\bsftp\b', cmd):
        return 'high', 'SFTP 접속'
    if re.search(r'\b(?:nc|ncat|netcat|socat)\b|/dev/tcp/', cmd):
        return 'high', '원시 소켓 전송 (nc/socat)'
    if re.search(r'http\.server|SimpleHTTPServer|php\s+-S', cmd):
        return 'high', '웹서버로 파일 노출'
    if re.search(r'\b(?:wget|curl|axel|aria2c|tftp|ftp|lftp)\b', cmd):
        return 'high', '외부 파일 다운로드'
    return 'high', '파일 전송'


def classify(cmd):
    hits = [(c, s, l) for c, s, l, rx in RULES if rx.search(cmd)]
    if not hits:
        return 'cmd', 'info', []
    labels, best = [], 0
    for _, s, l in hits:
        if l not in labels:
            labels.append(l)
        best = max(best, SEV_RANK[s])
    if '파일 전송' in labels:
        tsev, tlabel = transfer_detail(cmd)
        labels.insert(labels.index('파일 전송') + 1, tlabel)
        best = max(best, SEV_RANK[tsev])
    return hits[0][0], SEVS[best], labels


# ───────────────────────── 명령어 해설 ─────────────────────────
# 명령을 "무엇을 했는지 / 이 사고에서 어떤 의미인지 / 무엇을 확인할지" 문장으로 풀어 쓴다.
HIDDEN_RX = re.compile(r'/(?:tmp|var/tmp|dev/shm)/\.[^/\s]*')
CRED_FILES = [
    (r'/etc/shadow', '계정 비밀번호 해시가 담긴 /etc/shadow 를 열람했습니다. 해시를 가져가 크래킹하면 실제 비밀번호를 알아낼 수 있습니다.',
     '서버의 모든 계정 비밀번호를 바꾸는 것이 안전합니다.'),
    (r'wp-config\.php', '워드프레스 설정 파일(wp-config.php)을 열어봤습니다. 이 파일에는 DB 접속 계정과 비밀번호가 평문으로 들어 있어서, '
                        '공격자가 여기서 DB 비밀번호를 얻었을 가능성이 높습니다.', 'DB 비밀번호를 바꾸세요.'),
    (r'\.env\b|config\.php|database\.yml|settings\.py|application\.(?:yml|properties)',
     '애플리케이션 설정 파일을 열어봤습니다. 보통 DB·API 접속 정보(비밀번호, 키)가 들어 있습니다.', '파일에 든 비밀번호·키를 모두 교체하세요.'),
    (r'\.my\.cnf|\.pgpass', 'DB 클라이언트 자동 로그인 파일을 열어봤습니다. DB 비밀번호가 평문으로 저장되는 파일입니다.', 'DB 비밀번호를 바꾸세요.'),
    (r'id_rsa|id_ed25519|id_ecdsa', 'SSH 개인키 파일을 열어봤습니다. 이 키로 다른 서버에 비밀번호 없이 접속할 수 있습니다.',
     '이 키를 등록해 둔 다른 서버들의 authorized_keys 에서 키를 빼고 새 키로 바꾸세요.'),
    (r'\.aws/credentials|\.kube/config|\.docker/config\.json', '클라우드/컨테이너 접속 자격증명 파일을 열어봤습니다.',
     '해당 클라우드 키를 즉시 폐기·재발급하세요.'),
]
BASE_DESC = {
    'ls': '파일·폴더 목록을 보는 명령입니다.', 'cd': '작업 폴더를 옮기는 명령입니다.', 'pwd': '현재 위치(폴더)를 확인하는 명령입니다.',
    'df': '디스크 남은 용량을 확인하는 명령입니다.', 'du': '폴더별 용량을 확인하는 명령입니다.', 'free': '메모리 사용량을 확인하는 명령입니다.',
    'top': '실행 중인 프로세스와 CPU·메모리 사용량을 실시간으로 보는 명령입니다.', 'htop': '실행 중인 프로세스를 실시간으로 보는 명령입니다.',
    'kill': '프로세스를 종료하는 명령입니다.', 'pkill': '이름으로 프로세스를 찾아 종료하는 명령입니다.', 'killall': '같은 이름의 프로세스를 모두 종료하는 명령입니다.',
    'cp': '파일을 복사하는 명령입니다.', 'mv': '파일을 옮기거나 이름을 바꾸는 명령입니다.', 'ln': '파일 바로가기(링크)를 만드는 명령입니다.',
    'touch': '빈 파일을 만들거나 파일 시각을 바꾸는 명령입니다.', 'chown': '파일 소유자를 바꾸는 명령입니다.',
    'less': '파일 내용을 넘겨 보는 명령입니다.', 'more': '파일 내용을 넘겨 보는 명령입니다.', 'head': '파일 앞부분을 보는 명령입니다.',
    'tail': '파일 끝부분을 보는 명령입니다.', 'vi': '파일을 편집하는 명령입니다.', 'vim': '파일을 편집하는 명령입니다.', 'nano': '파일을 편집하는 명령입니다.',
    'awk': '텍스트에서 필요한 부분을 뽑아내는 명령입니다.', 'sed': '텍스트를 바꾸거나 걸러내는 명령입니다.', 'sort': '줄을 정렬하는 명령입니다.',
    'uniq': '중복 줄을 없애는 명령입니다.', 'wc': '줄·단어 수를 세는 명령입니다.', 'env': '환경 변수 목록을 보는 명령입니다. 비밀번호·토큰이 환경 변수에 들어 있으면 노출됩니다.',
    'lsof': '어떤 프로세스가 어떤 파일·포트를 쓰고 있는지 보는 명령입니다.', 'mount': '디스크를 연결(마운트)하는 명령입니다.',
    'dd': '디스크나 파일을 통째로 복사하는 저수준 명령입니다.', 'getent': '계정·그룹 정보를 조회하는 명령입니다.',
    'docker': '컨테이너를 다루는 명령입니다.', 'openssl': '암호화·인증서 도구입니다. 파일을 암호화하거나 암호화된 통신을 여는 데 쓰일 수 있습니다.',
    'strings': '바이너리 파일 안의 글자만 뽑아 보는 명령입니다.', 'file': '파일 종류를 확인하는 명령입니다.',
    'md5sum': '파일 해시(지문)를 계산하는 명령입니다.', 'sha256sum': '파일 해시(지문)를 계산하는 명령입니다.',
    'exit': '셸을 종료(로그아웃)했습니다.', 'logout': '로그아웃했습니다.', 'clear': '화면을 지운 명령입니다.',
    'reboot': '서버를 재부팅하는 명령입니다.', 'shutdown': '서버를 끄는 명령입니다.', 'ping': '상대 서버와 통신되는지 확인하는 명령입니다.',
    'dig': '도메인 주소(DNS)를 조회하는 명령입니다.', 'nslookup': '도메인 주소(DNS)를 조회하는 명령입니다.',
    'nmap': '다른 서버의 열린 포트를 스캔하는 명령입니다. 내부망의 다음 공격 대상을 찾는 행동일 수 있습니다.',
    'ssh-keygen': 'SSH 키 쌍을 만드는 명령입니다.', 'gcc': '소스 코드를 컴파일하는 명령입니다. 권한상승 공격 도구를 직접 빌드할 때 쓰이기도 합니다.',
    'make': '소스 코드를 빌드하는 명령입니다.', 'journalctl': '시스템 로그를 조회하는 명령입니다.', 'xxd': '파일을 16진수로 보여주는 명령입니다.',
    'unzip': 'zip 압축을 푸는 명령입니다.', 'gunzip': 'gzip 압축을 푸는 명령입니다.', 'lastlog': '계정별 마지막 로그인 시각을 보는 명령입니다.',
    'xmrig': '암호화폐(모네로) 채굴 프로그램입니다. 서버 자원을 몰래 채굴에 쓰는 악성 행위입니다.',
    'visudo': 'sudo 권한 설정 파일을 편집하는 명령입니다. 특정 계정에 root 권한을 주는 백도어로 쓰일 수 있습니다.',
    'usermod': '계정 설정을 바꾸는 명령입니다. 관리자 그룹(sudo, wheel)에 추가하면 root 권한을 얻게 됩니다.',
    'userdel': '계정을 삭제하는 명령입니다.', 'chage': '비밀번호 만료 정책을 바꾸는 명령입니다.', 'at': '정해진 시각에 명령을 한 번 실행하도록 예약하는 명령입니다.',
    'printf': '글자를 출력하는 명령입니다.', 'mkfifo': '프로세스 사이에 데이터를 넘기는 파이프 파일을 만드는 명령입니다. 리버스 셸을 만들 때 자주 쓰입니다.',
    'auditctl': '감사(audit) 기록 규칙을 바꾸는 명령입니다. -D 는 모든 감시 규칙을 지워 이후 행동이 기록되지 않게 합니다.',
}


def _shorten(s, n=70):
    s = s.strip()
    return s if len(s) <= n else s[:n - 1] + '…'


def _split_segments(cmd):
    """따옴표를 고려해 ; | && || & 로 명령을 나눈다 → [(segment, 뒤 구분자)]"""
    segs, buf, q, i = [], '', None, 0
    while i < len(cmd):
        c = cmd[i]
        if q:
            buf += c
            if c == q:
                q = None
        elif c in '\'"':
            q = c
            buf += c
        elif cmd.startswith('||', i) or cmd.startswith('&&', i):
            segs.append((buf, cmd[i:i + 2]))
            buf = ''
            i += 2
            continue
        elif c in ';|\n':
            segs.append((buf, c))
            buf = ''
        elif c == '&' and not buf.endswith('>') and cmd[i + 1:i + 2] != '>':
            segs.append((buf, '&'))
            buf = ''
        else:
            buf += c
        i += 1
    segs.append((buf, ''))
    out = []
    for s, sep in segs:
        s = s.strip().lstrip('(').rstrip(')').strip()
        if s:
            out.append([s, sep])
        elif out and sep:
            out[-1][1] = out[-1][1] or sep
    return out


def _parse_segment(seg):
    redir = []

    def rd(m):
        redir.append((m.group(1) or '1', m.group(2), m.group(3).strip('\'"')))
        return ' '
    body = re.sub(r'(\d?)(>>|&>|>)(?!&)\s*([^\s;&|<>]+)', rd, seg)
    body = re.sub(r'\d?>&\d', ' ', body)
    stdin = None
    m = re.search(r'<\s*([^\s;&|<>]+)', body)
    if m:
        stdin = m.group(1)
        body = body.replace(m.group(0), ' ')
    try:
        toks = shlex.split(body)
    except ValueError:
        toks = body.split()
    pre = {'sudo': None, 'nohup': False, 'env': {}}
    while toks:
        t = toks[0]
        if os.path.basename(t) == 'sudo':
            toks.pop(0)
            pre['sudo'] = 'root'
            while toks and toks[0].startswith('-'):
                o = toks.pop(0)
                if o in ('-u', '-g') and toks:
                    pre['sudo'] = toks.pop(0)
                elif o == '-l':
                    pre['sudo_l'] = True
            continue
        if t in ('nohup', 'time', 'exec', 'nice', 'command', 'builtin', 'setsid'):
            pre['nohup'] = pre['nohup'] or t in ('nohup', 'setsid')
            toks.pop(0)
            continue
        if re.match(r'^[A-Za-z_]\w*=', t):
            k, v = t.split('=', 1)
            pre['env'][k] = v
            toks.pop(0)
            continue
        break
    return toks, redir, stdin, pre


def _optval(args, short=None, long=None):
    for i, a in enumerate(args):
        if long and a == long and i + 1 < len(args):
            return args[i + 1]
        if long and a.startswith(long + '='):
            return a.split('=', 1)[1]
        if short and not a.startswith('--'):
            if a == short and i + 1 < len(args) and not args[i + 1].startswith('-'):
                return args[i + 1]
            if a.startswith(short) and len(a) > len(short):
                return a[len(short):]
    return None


def _positional(args, takes_value=()):
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith('-') and a != '-':
            skip = a in takes_value
            continue
        out.append(a)
    return out


def _url_host(s):
    m = re.search(r'(?:https?|ftp|sftp|tftp)://(?:[^@/\s]+@)?([^/:\s\'"]+)', s)
    return m.group(1) if m else None


def _sql_meaning(sql):
    s = sql.strip().rstrip(';')
    if re.match(r'(?i)show\s+databases', s):
        return '서버에 어떤 데이터베이스들이 있는지 목록을 확인'
    if re.match(r'(?i)show\s+tables', s):
        return '테이블 목록을 확인'
    m = re.match(r'(?i)use\s+`?(\w+)', s)
    if m:
        return f'{m[1]} 데이터베이스를 선택'
    m = re.search(r'(?i)into\s+(?:out|dump)file\s+[\'"]?([^\'"\s]+)', s)
    if m:
        return f'조회 결과를 서버의 {m[1]} 파일로 저장(데이터를 파일로 빼냄)'
    m = re.match(r'(?i)select\s+\*\s+from\s+`?([\w.]+)', s)
    if m:
        return f'{m[1]} 테이블의 모든 데이터를 조회'
    if re.match(r'(?i)select\b', s):
        return '데이터를 조회'
    if re.match(r'(?i)drop\s+(?:database|table)', s):
        return 'DB·테이블을 삭제'
    if re.match(r'(?i)create\s+user', s):
        return 'DB 계정을 새로 생성(나중에 다시 들어오기 위한 백도어일 수 있음)'
    if re.match(r'(?i)grant\b', s):
        return 'DB 계정에 권한을 부여'
    if re.match(r'(?i)(?:alter\s+user|set\s+password)', s):
        return 'DB 계정 비밀번호를 변경'
    if re.match(r'(?i)(?:update|delete|insert)\b', s):
        return '데이터를 수정·삭제·추가'
    return None


def explain_cmd(cmd):
    """명령 한 줄 → {'summary': [문장], 'details': [[용어, 문장]], 'check': [문장]}"""
    S, D, C = [], [], []

    def s(t):
        if t and t not in S:
            S.append(t)

    def d(term, t):
        if [term, t] not in D:
            D.append([term, t])

    def c(t):
        if t and t not in C:
            C.append(t)

    segs = _split_segments(cmd)
    parsed = [_parse_segment(seg) for seg, _ in segs]
    for i, ((seg, sep), (toks, redir, stdin, pre)) in enumerate(zip(segs, parsed)):
        piped_in = i > 0 and segs[i - 1][1] == '|'
        piped_out = sep == '|'
        bg = sep == '&'
        outs = [r for r in redir if r[2] != '/dev/null' and r[0] in ('1', '')]
        hide = any(r[2] == '/dev/null' and r[0] in ('1', '&') for r in redir)

        if pre.get('sudo_l'):
            s('sudo 로 어떤 명령을 root 권한으로 실행할 수 있는지 확인했습니다. 권한을 높일 방법을 찾는 정찰입니다.')
        if pre['sudo']:
            d(f'sudo{" -u " + pre["sudo"] if pre["sudo"] != "root" else ""}',
              f'{pre["sudo"]} 계정 권한으로 실행했습니다.' if pre['sudo'] != 'root' else 'root(관리자) 권한으로 실행했습니다.')
        for k, v in pre['env'].items():
            if k in ('HISTFILE', 'HISTSIZE', 'HISTFILESIZE') and v in ('/dev/null', '0', ''):
                s('명령 기록(히스토리)이 저장되지 않도록 설정했습니다. 이후 명령은 auditd 같은 다른 로그로만 확인할 수 있습니다.')
            elif k == 'LD_PRELOAD':
                s(f'{v} 라이브러리를 프로그램에 강제로 끼워 넣어 실행했습니다. 루트킷이나 권한상승에 쓰이는 수법입니다.')
        if not toks:
            continue
        name = os.path.basename(toks[0])
        args = toks[1:]
        text = ' '.join(args)

        if name == 'whoami':
            s('지금 어떤 계정으로 들어와 있는지 확인했습니다. 침입 직후 자기 권한을 파악하는 전형적인 첫 명령입니다.')
        elif name == 'id':
            s('현재 계정의 UID와 소속 그룹을 확인했습니다. uid=0 이면 root(최고 관리자) 권한이라는 뜻입니다.')
        elif name == 'uname':
            s('서버의 커널 버전과 OS 정보를 확인했습니다. 공격자는 이 정보로 쓸 수 있는 권한상승 취약점을 찾습니다.')
        elif name == 'hostname':
            s('서버 이름을 확인했습니다. 어떤 서버에 들어왔는지 파악하는 정찰입니다.')
        elif name in ('w', 'who'):
            s('지금 서버에 접속해 있는 사람을 확인했습니다. 관리자가 보고 있는지 살피는 행동일 수 있습니다.')
        elif name == 'last':
            s('과거 로그인 기록을 확인했습니다. 관리자가 언제 접속하는지 파악하려는 것일 수 있습니다.')
        elif name in ('ss', 'netstat'):
            s('서버에 열려 있는 포트와 그 포트를 쓰는 프로그램을 확인했습니다. DB(3306, 5432) 같은 내부 서비스를 찾는 정찰입니다.')
        elif name in ('ifconfig', 'ip') and (name == 'ifconfig' or args[:1] and args[0] in ('a', 'addr', 'r', 'route', 'neigh')):
            s('서버의 IP 주소와 네트워크 구성을 확인했습니다. 내부망에서 다음에 노릴 서버를 찾는 정찰일 수 있습니다.')
        elif name == 'ps':
            s('실행 중인 프로세스 목록을 봤습니다.')
        elif name == 'grep':
            pat = next((a for a in args if not a.startswith('-')), '')
            readable = pat.replace('\\|', ' 또는 ').replace('|', ' 또는 ')
            if piped_in:
                prev = os.path.basename(parsed[i - 1][0][0]) if parsed[i - 1][0] else ''
                if prev == 'ps':
                    s(f'그중 "{readable}" 이(가) 들어간 것만 골라 봤습니다. 즉 {readable} 프로그램이 이 서버에서 돌고 있는지 확인한 것입니다.')
                else:
                    s(f'앞 결과에서 "{readable}" 이(가) 들어간 줄만 골라냈습니다.')
            else:
                files = _positional(args, ('-e', '-f', '-m', '-A', '-B', '-C'))[1:]
                s(f'"{readable}" 문자열을 {", ".join(files) or "파일"} 에서 찾았습니다.')
        elif name in ('cat', 'less', 'more', 'head', 'tail', 'vi', 'vim', 'nano', 'strings'):
            files = _positional(args, ('-n',))
            hit = False
            for f in files:
                for rx, desc, chk in CRED_FILES:
                    if re.search(rx, f):
                        s(desc)
                        c(chk)
                        hit = True
                        break
                else:
                    if f == '/etc/passwd':
                        s('서버에 어떤 계정들이 있는지 목록(/etc/passwd)을 봤습니다. 비밀번호는 들어 있지 않지만 공격할 계정을 고르는 데 쓰입니다.')
                        hit = True
                    elif f in ('/etc/hosts', '/etc/issue', '/etc/os-release') or f.endswith('release'):
                        s(f'{f} 를 읽어 서버 환경을 확인했습니다.')
                        hit = True
            if not hit and files and name == 'cat' and not outs:
                s(f'{", ".join(files[:3])} 파일 내용을 화면에 출력했습니다.')
            elif not hit and files and name in ('vi', 'vim', 'nano'):
                s(f'{files[0]} 파일을 편집기로 열었습니다. 내용을 바꿨을 수 있습니다.')
        elif name in ('mysql', 'mariadb'):
            user = _optval(args, '-u', '--user') or '(기본)'
            host = _optval(args, '-h', '--host')
            sql = _optval(args, '-e', '--execute')
            s(f'{user} 계정으로 MySQL 데이터베이스에 접속했습니다' + (f' (DB 서버 {host})' if host else '') + '.')
            if sql:
                meaning = _sql_meaning(sql)
                s(f'접속하자마자 "{_shorten(sql, 50)}" 를 실행해 {meaning or "SQL 을 실행"}했습니다.')
        elif name in ('mysqldump', 'mariadb-dump'):
            user = _optval(args, '-u', '--user') or '(기본)'
            dbs = _positional(args, ('-h', '--host', '-u', '--user', '-P', '--port', '-r', '--result-file'))
            what = '모든 데이터베이스' if ('--all-databases' in args or '-A' in args) else (', '.join(dbs[:4]) + ' 데이터베이스' if dbs else '데이터베이스')
            s(f'MySQL 에 {user} 계정으로 접속해 {what}를 통째로 뽑아냈습니다(DB 덤프). 결과는 SQL 문장 형태의 텍스트로, 테이블 구조와 데이터가 전부 들어 있습니다.')
            c('덤프된 DB 에 개인정보·결제정보가 있다면 유출 신고 대상인지 검토하세요.')
        elif name in ('pg_dump', 'pg_dumpall'):
            db = (_positional(args, ('-U', '-h', '-p', '-f', '-d', '-F', '-t', '-n')) or [_optval(args, '-d', '--dbname') or ''])[0]
            if name == 'pg_dumpall':
                s('PostgreSQL 의 모든 데이터베이스와 DB 계정 정보를 통째로 뽑아냈습니다(DB 덤프).')
            else:
                s(f'PostgreSQL 의 {db or ""} 데이터베이스 전체를 뽑아냈습니다(DB 덤프).'.replace('의  데이터', '의 데이터'))
            c('덤프된 DB 에 개인정보가 있다면 유출 신고 대상인지 검토하세요.')
        elif name in ('mongodump', 'mongoexport'):
            s('MongoDB 데이터를 파일로 뽑아냈습니다(DB 덤프).')
        elif name == 'redis-cli':
            rdb = _optval(args, None, '--rdb')
            if rdb:
                s(f'Redis 에 저장된 전체 데이터를 {rdb} 파일로 내려받았습니다(DB 덤프).')
            else:
                s('Redis 데이터베이스에 접속했습니다.')
        elif name in ('psql', 'sqlite3', 'mongo', 'mongosh'):
            s(f'{name} 로 데이터베이스에 접속했습니다.')
        elif name in ('gzip', 'bzip2', 'xz') and piped_in:
            if outs:
                s(f'그 결과를 압축해서 {outs[0][2]} 파일로 저장했습니다.')
                outs = []
            else:
                s('그 결과를 압축했습니다.')
        elif name in ('gzip', 'bzip2', 'xz'):
            s('파일을 압축했습니다.' if args else '데이터를 압축했습니다. (다른 명령에 딸려 자동으로 실행된 압축 단계일 수 있습니다)')
        elif name == 'tar':
            flags = args[0].lstrip('-') if args else ''
            if 'c' in flags:
                arch = _optval(args, '-f') if '-f' in args else (args[1] if len(args) > 1 else '')
                srcs = [a for a in args[2:] if not a.startswith('-')] if not '-f' in args else _positional(args[1:], ('-f',))[1:]
                s(f'{", ".join(srcs) or "여러 파일"} 를 {arch or "파일"} 하나로 묶어 압축했습니다. 밖으로 빼내기 전에 자료를 한 파일로 모으는 단계에서 자주 보입니다.')
            elif 'x' in flags:
                s('압축 파일을 풀었습니다. 외부에서 받아온 도구를 푸는 것일 수 있습니다.')
            elif 't' in flags:
                s('압축 파일 안의 목록을 확인했습니다.')
        elif name in ('zip', '7z', '7za', 'rar'):
            s('파일을 압축했습니다. 비밀번호를 걸어 압축하면 유출 내용 확인이 어려워집니다.' if '-P' in args or '-p' in ' '.join(args) else '파일을 압축했습니다.')
        elif name == 'split':
            size = _optval(args, '-b')
            s(f'파일을 {size or "여러"} 크기로 잘게 쪼갰습니다. 큰 파일을 눈에 덜 띄게 나눠 빼내려는 것일 수 있습니다.')
        elif name == 'curl':
            up = _optval(args, '-T', '--upload-file')
            form = re.search(r'(?:-F|--form)\s+\S*@([^\s;\'"]+)', text)
            data = re.search(r'(?:-d|--data(?:-binary)?)\s+@(\S+)', text)
            host = _url_host(text) or '외부 서버'
            if up or form or data:
                f = up or (form or data).group(1)
                s(f'이 서버의 {f} 파일을 외부 서버({host})로 업로드했습니다. 서버의 데이터가 밖으로 나간 것(유출)입니다.')
                c(f'{host} 주소를 차단하고, 업로드된 파일에 무엇이 들어 있었는지 확인하세요.')
            else:
                out = _optval(args, '-o', '--output')
                s(f'외부 서버({host})에서 파일을 내려받았습니다' + (f'(→ {out} 로 저장)' if out else '') + '.')
                c(f'{host} 주소를 차단하고, 내려받은 파일을 확보해 분석하세요.')
            user = _optval(args, '-u', '--user')
            if user:
                d('--user', f'상대 서버에 {user.split(":")[0]} 계정으로 로그인했습니다.')
        elif name == 'wget':
            host = _url_host(text) or '외부 서버'
            out = _optval(args, '-O', '--output-document')
            s(f'외부 서버({host})에서 파일을 내려받았습니다' + (f'(→ {out} 로 저장)' if out else '') + '.')
            if '-q' in args:
                d('-q', '진행 상황을 출력하지 않도록 조용히 받았습니다.')
            c(f'{host} 주소를 차단하고, 내려받은 파일을 확보해 분석하세요.')
        elif name in ('sh', 'bash', 'zsh') and piped_in and not args:
            s('내려받은 내용을 파일로 저장하지 않고 바로 셸로 실행했습니다. 악성코드를 설치할 때 흔히 쓰는 방식이라 흔적이 디스크에 잘 남지 않습니다.')
        elif name in ('bash', 'sh') and '-i' in args and '/dev/tcp/' in seg:
            m = re.search(r'/dev/tcp/([^/\s]+)/(\d+)', seg)
            s(f'이 서버의 셸을 {m[1]}:{m[2]} 로 연결했습니다(리버스 셸). 공격자가 그 주소에서 이 서버를 원격으로 조종할 수 있게 됩니다.' if m else '리버스 셸을 연결했습니다.')
            if m:
                c(f'{m[1]} 주소를 차단하세요.')
        elif name == 'scp':
            files = _positional(args, ('-P', '-i', '-o', '-F', '-l', '-S', '-c'))
            if '-f' in args or any(re.fullmatch(r'-[A-Za-z]*f', a) for a in args):
                f = files[-1] if files else '파일'
                s(f'외부에서 이 서버의 {f} 를 scp 로 가져갔습니다(유출). "scp -f" 는 공격자가 자기 PC에서 "scp 계정@이서버:{f} ." 처럼 '
                  '내려받기를 실행했을 때 이 서버 쪽에서 자동으로 실행되는 명령이라, 이 기록이 있으면 파일이 밖으로 복사된 것입니다.')
                c('이 파일에 무엇이 들어 있었는지 확인하세요. 같은 세션의 접속 IP 가 파일을 받아간 곳입니다.')
            elif any(re.fullmatch(r'-[A-Za-z]*t', a) for a in args):
                s(f'외부에서 이 서버의 {files[-1] if files else "어딘가"} 위치로 scp 로 파일을 올렸습니다(반입). 공격 도구를 가져온 것일 수 있습니다.')
            elif files and re.match(r'^[^/\s]*:', files[-1]):
                s(f'이 서버의 {", ".join(files[:-1])} 를 외부 서버 {files[-1].split(":")[0]} 로 복사했습니다(유출).')
                c(f'{files[-1].split(":")[0].split("@")[-1]} 주소를 차단하고 복사된 파일 내용을 확인하세요.')
            elif files:
                s(f'외부 서버 {files[0].split(":")[0]} 에서 파일을 이 서버로 가져왔습니다(반입).')
        elif name == 'rsync':
            files = _positional(args, ('-e', '--rsh'))
            if files and re.match(r'^[^/\s]*:', files[-1]):
                s(f'{", ".join(files[:-1])} 를 외부 서버 {files[-1].split(":")[0]} 로 동기화(복사)했습니다(유출).')
            elif files:
                s('rsync 로 파일을 복사했습니다.')
        elif name in ('nc', 'ncat', 'netcat'):
            pos = _positional(args, ('-p', '-w', '-e', '-c', '-s'))
            ex = _optval(args, '-e') or _optval(args, '-c')
            if ex:
                s(f'접속이 오면 {ex} 를 실행하도록 nc 를 띄웠습니다. 원격에서 이 서버 명령을 실행할 수 있게 하는 백도어(리버스 셸)입니다.')
            elif any(a.startswith('-') and 'l' in a for a in args):
                s(f'{(pos or ["?"])[-1]} 포트를 열고 접속을 기다렸습니다. 파일을 받거나 백도어로 쓰일 수 있습니다.')
            elif stdin and len(pos) >= 2:
                s(f'{stdin} 파일을 {pos[0]}:{pos[1]} 로 그대로 전송했습니다(유출).')
                c(f'{pos[0]} 주소를 차단하세요.')
            elif len(pos) >= 2:
                s(f'nc 로 {pos[0]}:{pos[1]} 에 직접 연결했습니다.' + (' 받은 데이터를 파일로 저장했습니다.' if outs else ''))
        elif name == 'socat':
            s('socat 으로 네트워크 연결을 중계했습니다. 터널이나 리버스 셸을 만들 때 쓰입니다.')
        elif name == 'ssh':
            pos = _positional(args, ('-p', '-i', '-o', '-l', '-R', '-L', '-D', '-F', '-J'))
            if _optval(args, '-R'):
                s(f'역방향 터널(-R {_optval(args, "-R")})을 열었습니다. 외부에서 이 서버 안쪽으로 들어올 통로를 만든 것입니다.')
            elif _optval(args, '-L') or _optval(args, '-D'):
                s('SSH 터널을 열어 다른 네트워크로 통신을 중계했습니다.')
            elif pos:
                s(f'이 서버에서 다른 서버({pos[0]})로 다시 SSH 접속했습니다. 내부망의 다른 서버로 옮겨가는 측면 이동일 수 있습니다.')
        elif name == 'mkdir':
            dirs = _positional(args, ('-m',))
            s(f'{", ".join(dirs)} 폴더를 만들었습니다.')
        elif name == 'chmod':
            mode = args[0] if args else ''
            files = args[1:]
            if re.search(r'\+x|^0?7[0-7]{2}$', mode):
                s(f'{", ".join(files)} 에 실행 권한을 줬습니다. 방금 받아온 파일을 실행하려는 준비 단계입니다.')
            elif re.search(r'\+s|^[2467][0-7]{3}$', mode):
                s(f'{", ".join(files)} 에 SUID 를 걸었습니다. 누가 실행하든 파일 주인(보통 root) 권한으로 실행되므로 권한상승 백도어가 됩니다.')
                c(f'{", ".join(files)} 의 SUID 를 제거(chmod u-s)하세요.')
            else:
                s(f'{", ".join(files)} 의 권한을 {mode} 로 바꿨습니다.')
        elif name == 'chattr' and args and args[0].startswith('+i'):
            s(f'{", ".join(args[1:])} 를 root 도 지우거나 고칠 수 없게 잠갔습니다. 백도어 파일을 지키려는 수법이며, chattr -i 로 풀 수 있습니다.')
        elif name in ('useradd', 'adduser'):
            uid = _optval(args, '-u', '--uid')
            pos = _positional(args, ('-u', '-g', '-G', '-s', '-d', '-c', '-p', '-e', '-k', '--uid', '--gid', '--shell', '--home'))
            uname = pos[-1] if pos else '?'
            if uid == '0':
                s(f'"{uname}" 라는 새 계정을 만들면서 UID 를 0 으로 지정했습니다. UID 0 은 root 와 똑같은 최고 권한이라, 이름만 다른 숨은 root 계정(백도어)을 만든 것입니다.')
                if '-o' in args or '--non-unique' in args:
                    d('-o', '이미 root 가 쓰고 있는 UID 0 을 중복해서 쓸 수 있게 허용하는 옵션입니다.')
                if '-M' in args:
                    d('-M', '홈 폴더를 만들지 않아 눈에 덜 띄게 했습니다.')
                c(f'/etc/passwd 에서 {uname} 처럼 UID 가 0 인 계정을 찾아 삭제하세요.')
            else:
                s(f'새 계정 "{uname}" 을(를) 만들었습니다. 나중에 다시 들어오기 위한 계정일 수 있습니다.')
                c(f'{uname} 계정이 정상 계정인지 확인하세요.')
        elif name == 'chpasswd':
            prev = segs[i - 1][0] if piped_in else ''
            m = re.search(r'([\w.-]+):(\S+?)[\'"]?\s*$', prev)
            s(f'"{m[1]}" 계정의 비밀번호를 설정했습니다. 만들어 둔 계정으로 나중에 다시 로그인하려는 것입니다.' if m
              else '계정 비밀번호를 일괄로 설정했습니다.')
        elif name == 'passwd':
            pos = _positional(args)
            s(f'{pos[0] if pos else "현재"} 계정의 비밀번호를 바꿨습니다. 원래 주인이 로그인하지 못하게 하거나, 계정을 차지하려는 것일 수 있습니다.')
        elif name == 'echo' and any('authorized_keys' in r[2] for r in redir):
            path = next(r[2] for r in redir if 'authorized_keys' in r[2])
            who = 'root' if path.startswith(('/root', '~')) else (path.split('/')[2] if path.startswith('/home/') else '해당')
            s(f'SSH 공개키를 {who} 계정의 authorized_keys 에 추가했습니다. 이 키의 짝(개인키)을 가진 사람은 비밀번호 없이 언제든 다시 접속할 수 있는 백도어입니다.')
            m = re.search(r'ssh-\S+\s+\S+\s+(\S+@\S+?)[\'"]?(?:\s|$)', seg)
            if m:
                d(m[1], '키 끝에 붙은 이름은 키를 만든 컴퓨터의 "사용자@호스트" 입니다. 공격자 환경을 짐작할 단서가 됩니다.')
            c(f'{path} 에서 모르는 키를 지우세요.')
        elif name == 'echo' and outs and not outs[0][2].startswith('/var/log/'):
            s(f'{outs[0][2]} 파일에 내용을 {"덧붙였" if outs[0][1] == ">>" else "썼"}습니다.')
        elif name == 'crontab':
            appends = re.search(r'crontab\s+-l\b', cmd) and re.search(r'\|\s*crontab\s+-\s*$', cmd)
            if args == ['-l']:
                if not appends:
                    s('현재 등록된 예약 작업(cron) 목록을 확인했습니다.')
            elif args and args[0] in ('-', '-e') or (args and not args[0].startswith('-')):
                if appends:
                    s('기존 예약 작업은 그대로 둔 채 새 작업을 한 줄 덧붙여 다시 등록했습니다. 관리자가 기존 목록만 보고 지나치기 쉽게 만드는 방법입니다.')
                s('이렇게 등록한 예약 작업(cron)은 서버가 재부팅되거나 프로세스를 죽여도 다시 실행되므로 "지속성 확보" 수법입니다.'
                  if appends else '예약 작업(cron)을 새로 등록했습니다. 서버가 재부팅되거나 프로세스를 죽여도 다시 실행되게 하는 "지속성 확보" 수법입니다.')
                m = re.search(r'((\*/(\d+)|@reboot|@hourly|@daily)(?:\s+\*){0,4})\s+(/[^\s\'"]+)', cmd)
                if m:
                    when = f'{m[3]}분마다' if m[3] else {'@reboot': '부팅할 때마다', '@hourly': '1시간마다', '@daily': '하루에 한 번'}[m[2]]
                    d(f'{m[1]} {m[4]}', f'"{when} {m[4]} 를 실행하라"는 예약 작업 설정입니다.')
                c('crontab -l 과 /etc/cron* 에서 이 항목을 지우세요.')
            elif args[:1] == ['-r']:
                s('예약 작업을 모두 지웠습니다.')
        elif name == 'history':
            if '-c' in args:
                s('지금까지 입력한 명령 기록을 셸에서 지웠습니다. 흔적을 감추려는 행동입니다. 이미 파일에 저장된 기록이나 auditd 기록은 남아 있을 수 있습니다.')
            elif '-w' in args or '-d' in args:
                s('명령 기록을 덮어쓰거나 일부를 지웠습니다. 흔적을 감추려는 행동입니다.')
            else:
                s('입력했던 명령 기록을 확인했습니다.')
        elif name in ('unset', 'export') and any(a.startswith('HIST') for a in args):
            s('이후에 치는 명령이 히스토리 파일(~/.bash_history)에 저장되지 않도록 설정했습니다. 이 다음 명령들은 auditd 등 다른 로그로만 확인할 수 있습니다.')
        elif name == 'set' and '+o' in args and 'history' in args:
            s('명령 기록을 끄도록 설정했습니다. 흔적을 감추려는 행동입니다.')
        elif name in ('rm', 'shred', 'unlink'):
            files = _positional(args, ('-n', '-s'))
            logs = [f for f in files if re.search(r'_history|/var/log/|\.log\b|wtmp|btmp|lastlog', f)]
            how = '복구할 수 없게 덮어쓴 뒤 ' if name == 'shred' else ''
            if logs:
                s(f'기록 파일 {", ".join(logs)} 를 {how}지웠습니다. 흔적을 지우는 행동입니다.')
            elif files:
                s(f'{", ".join(files[:4])} 를 {how}삭제했습니다.' + (' 공격에 쓴 작업 파일을 정리한 것일 수 있습니다.' if any(HIDDEN_RX.search(f) for f in files) else ''))
        elif name == 'truncate' and args:
            s(f'{", ".join(_positional(args, ("-s", "--size")))} 파일 내용을 비웠습니다. 로그라면 흔적 삭제입니다.')
        elif name == 'touch' and (_optval(args, '-r') or _optval(args, '-d') or _optval(args, '-t')):
            ref = _optval(args, '-r')
            s(f'파일 수정 시각을 {ref + " 와 같게" if ref else "임의 날짜로"} 위조했습니다. 바꾼 파일이 최근에 수정된 것처럼 보이지 않게 하려는 수법입니다(타임스톰핑).')
        elif name in ('python', 'python2', 'python3', 'perl', 'ruby', 'php'):
            code = _optval(args, '-c') or _optval(args, '-e') or _optval(args, '-r') or ''
            if 'pty.spawn' in code:
                s('제대로 된 대화형 터미널(TTY)을 얻으려고 파이썬으로 bash 를 새로 띄웠습니다. 리버스 셸 등으로 들어온 직후 자주 쓰는 명령입니다.')
            elif re.search(r'socket|subprocess|os\.dup2', code):
                s('스크립트 한 줄로 네트워크 연결을 열고 셸을 붙였습니다. 리버스 셸입니다.')
            elif re.search(r'http\.server|SimpleHTTPServer', text) or name == 'php' and '-S' in args:
                s('현재 폴더를 웹서버로 열었습니다. 외부에서 이 서버의 파일을 내려받을 수 있게 됩니다.')
            elif code:
                s(f'{name} 코드를 한 줄로 바로 실행했습니다.')
            elif args:
                s(f'{args[0]} 스크립트를 실행했습니다.')
        elif name == 'base64' and ('-d' in args or '--decode' in args):
            s('Base64 로 숨겨둔 내용을 원래대로 풀었습니다. 악성 스크립트를 감출 때 흔히 쓰입니다.')
        elif name == 'find':
            if re.search(r'-perm\s+(?:-4000|/4000|-u=s|-2000)', text):
                s('SUID 권한이 걸린 프로그램을 찾았습니다. 이런 프로그램의 약점을 이용해 root 권한을 얻으려는 정찰입니다.')
            elif re.search(r'-name\s+\S*(?:\.sql|\.bak|\.env|config|backup|\.key|\.pem)', text):
                s('설정·백업·DB 파일처럼 값나가는 파일을 찾았습니다.')
            else:
                s('파일을 검색했습니다.')
        elif name in ('systemctl', 'service'):
            act = next((a for a in args if a in ('start', 'stop', 'restart', 'enable', 'disable', 'status', 'reload')), None)
            svc = next((a for a in args if not a.startswith('-') and a != act), '')
            if name == 'service' and len(args) >= 2:
                svc, act = args[0], args[1]
            if act == 'stop' and re.search(r'audit|syslog|journal', svc):
                s(f'로그를 기록하는 {svc} 서비스를 멈췄습니다. 이후 행동이 기록되지 않게 하려는 것입니다.')
            elif act == 'enable':
                s(f'{svc} 서비스를 부팅할 때 자동으로 실행되게 등록했습니다. 악성 서비스라면 지속성 확보입니다.')
            elif act:
                verb = {'start': '시작', 'stop': '중지', 'restart': '재시작', 'disable': '자동 실행 해제',
                        'status': '상태 확인', 'reload': '설정 다시 읽기'}[act]
                s(f'{svc} 서비스를 {verb}했습니다.')
        elif name == 'iptables' and ('-F' in args or '--flush' in args):
            s('방화벽 규칙을 전부 지웠습니다. 외부 접속을 막던 보호가 사라집니다.')
        elif name == 'setenforce' and args[:1] == ['0']:
            s('SELinux 보안 기능을 껐습니다.')
        elif name in ('apt', 'apt-get', 'yum', 'dnf'):
            if args[:1] == ['update']:
                s('설치할 수 있는 패키지 목록을 최신으로 갱신했습니다. 일반적인 관리 작업입니다.')
            elif args[:1] == ['install']:
                s(f'{", ".join(args[1:4])} 패키지를 설치했습니다.')
            else:
                s('패키지를 관리했습니다.')
        elif name == 'ls':
            pos = _positional(args)
            s(f'{", ".join(pos) or "현재"} 폴더 안의 파일 목록을 봤습니다.' + (' 숨김 파일까지 자세히 봤습니다.' if any('a' in a for a in args if a.startswith('-')) else ''))
        elif name == 'cd':
            s(f'{args[0] if args else "홈"} 폴더로 이동했습니다.')
        elif name == 'su':
            pos = _positional(args, ('-c', '-s'))
            s(f'{pos[0] if pos else "root"} 계정으로 전환했습니다.')
        elif toks[0].startswith(('./', '/tmp/', '/dev/shm/', '/var/tmp/')) or (toks[0].startswith('/') and HIDDEN_RX.search(toks[0])):
            s(f'{toks[0]} 프로그램을 직접 실행했습니다. 기본 프로그램이 아니라 따로 가져다 놓은 파일입니다.')
            c(f'{toks[0]} 파일을 확보해 분석하고, ps 로 아직 실행 중인지 확인하세요.')
        elif name in BASE_DESC:
            s(BASE_DESC[name])

        if pre['nohup'] or bg:
            d('nohup … &' if pre['nohup'] and bg else ('nohup' if pre['nohup'] else '&'),
              '접속을 끊어도 프로그램이 계속 돌아가도록 백그라운드로 실행했습니다.' if pre['nohup'] else '백그라운드로 실행했습니다.')
        if hide:
            d('>/dev/null', '출력(이나 오류 메시지)을 버려 화면에 흔적이 남지 않게 했습니다.')
        for fd, op, path in outs:
            if 'authorized_keys' in path:
                continue
            if re.match(r'/var/log/', path) and op == '>' and name in ('echo', 'cat', ':', 'true', 'printf') or not toks:
                s(f'{path} 로그 파일의 내용을 비웠습니다. 흔적 삭제입니다.')
            elif name != 'echo':
                s(f'결과를 {path} 파일로 {"덧붙여 " if op == ">>" else ""}저장했습니다.')
        for tok in toks:
            if HIDDEN_RX.search(tok):
                d(HIDDEN_RX.search(tok).group(0), '점(.)으로 시작하는 이름은 ls 로 잘 안 보이는 숨김 폴더·파일입니다. 공격자가 작업 공간으로 자주 씁니다.')
                break
        for k, a in enumerate(args):
            if name in ('mysql', 'mysqldump', 'mariadb', 'mariadb-dump') and re.match(r'^(?:-p|--password=)(.+)', a):
                d(f'-p{a[2:] if a.startswith("-p") else a.split("=", 1)[1]}',
                  '비밀번호가 명령에 그대로 적혀 있습니다. 공격자가 DB 비밀번호를 이미 알고 있었다는 뜻이고(예: 설정 파일에서 탈취), 이 비밀번호는 노출된 것으로 보고 바꿔야 합니다.')
    return {'summary': S[:5], 'details': D[:6], 'check': C[:3]}


LOOPBACK = {'localhost', '127.0.0.1', '::1', '0.0.0.0', 'ip6-localhost'}


def host_kind(host, self_ips=()):
    """'self' | 'private' | 'public' | 'domain'"""
    if host in LOOPBACK or host.startswith('127.') or host in self_ips:
        return 'self'
    try:
        a = ipaddress.ip_address(host)
        return 'private' if (a.is_private or a.is_link_local) else 'public'
    except ValueError:
        return 'domain'


def outbound_targets(cmd):
    """명령에서 '이 서버 → 다른 곳' 으로 나간 연결의 목적지를 뽑는다."""
    out = []

    def add(host, port, proto, what, user=None):
        host = (host or '').strip('[]').rstrip('/').lower()
        if not host or not re.match(r'^[\w.\-:]+$', host) or host.startswith('-'):
            return
        if any((o['host'], o['proto'], o['what']) == (host, proto, what) for o in out):
            return
        out.append({'host': host, 'port': port, 'proto': proto, 'what': what, 'user': user or None})

    for seg, _ in _split_segments(cmd):
        toks, redir, stdin, pre = _parse_segment(seg)
        if toks:
            name, args = os.path.basename(toks[0]), toks[1:]
            if name in ('ssh', 'mosh'):
                pos = _positional(args, ('-p', '-i', '-o', '-l', '-L', '-R', '-D', '-F', '-J', '-b', '-c', '-E', '-e',
                                         '-m', '-O', '-Q', '-S', '-W', '-w', '-B', '-I'))
                if pos:
                    user, _, host = pos[0].rpartition('@')
                    tun = any(_optval(args, o) for o in ('-L', '-R', '-D'))
                    add(host, _optval(args, '-p') or '22', 'ssh',
                        'SSH 터널' if tun else ('SSH 접속 + 원격 명령' if len(pos) > 1 else 'SSH 접속'), user or _optval(args, '-l'))
                j = _optval(args, '-J')
                if j:
                    add(j.rpartition('@')[2].split(':')[0], None, 'ssh', 'SSH 경유(점프) 서버')
            elif name in ('scp', 'rsync', 'sftp'):
                if name == 'scp' and any(re.fullmatch(r'-[A-Za-z]*[ft]', a) for a in args):
                    pass  # scp -f/-t 는 들어온 접속의 서버 쪽 동작
                elif name == 'sftp':
                    pos = _positional(args, ('-P', '-i', '-o', '-F', '-b', '-J'))
                    if pos:
                        u, _, h = pos[0].rpartition('@')
                        add(h.split(':')[0], _optval(args, '-P') or '22', 'sftp', 'SFTP 접속', u)
                else:
                    pos = _positional(args, ('-P', '-i', '-o', '-F', '-l', '-S', '-c', '-e', '--rsh', '-J'))
                    for k, a in enumerate(pos):
                        m = re.match(r'^(?:([^@/\s]+)@)?([^:/\s]+):', a)
                        if m and not a.startswith('/'):
                            add(m[2], _optval(args, '-P') or '22', name,
                                '파일 보냄 (업로드)' if k == len(pos) - 1 else '파일 가져옴 (다운로드)', m[1])
            elif name in ('curl', 'wget', 'lftp', 'ftp', 'tftp', 'axel', 'aria2c'):
                up = name == 'curl' and (_optval(args, '-T', '--upload-file')
                                         or re.search(r'(?:-F|--form)\s+\S*@|--data(?:-binary)?\s+@|\s-d\s*@', seg))
                for u in re.findall(r'((?:https?|ftps?|sftp|tftp)://[^\s\'"]+)', seg):
                    m = re.match(r'(\w+)://(?:([^@/\s:]+)(?::[^@/\s]*)?@)?(\[[^\]]+\]|[^/:\s]+)(?::(\d+))?', u)
                    if m:
                        add(m[3], m[4], m[1], '파일 보냄 (업로드)' if up else '파일 내려받음', m[2])
                if name in ('ftp', 'lftp', 'tftp'):
                    pos = _positional(args, ('-u', '-p', '-e'))
                    if pos and '://' not in pos[0]:
                        add(pos[0].rpartition('@')[2], None, name, 'FTP 접속')
            elif name in ('nc', 'ncat', 'netcat', 'telnet'):
                if not any(a.startswith('-') and not a.startswith('--') and 'l' in a[1:] for a in args):
                    pos = _positional(args, ('-p', '-w', '-e', '-c', '-s', '-i', '-q', '-x'))
                    if pos:
                        what = '리버스 셸' if (_optval(args, '-e') or _optval(args, '-c')) else \
                            '파일 보냄 (업로드)' if stdin else ('텔넷 접속' if name == 'telnet' else 'TCP 직접 연결')
                        add(pos[0], pos[1] if len(pos) > 1 else None, name, what)
            elif name == 'socat':
                for h, prt in re.findall(r'TCP[46]?:([\w.\-]+):(\d+)', seg, re.I):
                    add(h, prt, 'tcp', 'socat 연결')
            elif name in ('mysql', 'mariadb', 'mysqldump', 'psql', 'pg_dump', 'redis-cli', 'mongo', 'mongosh', 'mongodump'):
                h = _optval(args, '-h', '--host')
                if h and h not in LOOPBACK:
                    add(h, _optval(args, '-P' if name.startswith(('mysql', 'maria')) else '-p', '--port'), 'db',
                        'DB 접속 후 덤프' if 'dump' in name else 'DB 접속')
            elif name == 'nmap':
                for t in _positional(args, ('-p', '-oN', '-oX', '-oG', '-oA', '-iL', '--top-ports', '-e', '-S')):
                    add(t.split('/')[0], None, 'scan', '포트 스캔')
        for h, prt in re.findall(r'/dev/(?:tcp|udp)/([^/\s]+)/(\d+)', seg):
            add(h, prt, 'tcp', '리버스 셸' if re.search(r'-i\b|[0-2]>&[0-2]', seg) else 'TCP 직접 연결')
    return out


# 파일 작업 종류 → (아이콘 구분, 위험도)
FILE_OP_KIND = {
    '외부로 유출': 'out', '외부에서 반입': 'in', '삭제': 'del', '이동': 'mv', '복사': 'cp', '저장': 'save', '생성': 'new',
    '압축 생성': 'zip', '압축에 포함': 'zip', '압축 해제': 'unzip', '실행': 'exec', '권한 변경': 'perm', '시각 위조': 'perm',
    '내려받아 저장': 'in', '열람': 'read',
}


def file_ops(cmd, cwd=None):
    """명령이 건드린 파일 → [{'op', 'path', 'to'?, 'how'}]"""
    ops = []

    def norm(pth):
        pth = pth.strip('\'"')
        if cwd and pth and not pth.startswith(('/', '~', '$')) and not re.match(r'^[^/\s]*:', pth):
            pth = cwd.rstrip('/') + '/' + pth.lstrip('./')
        return pth

    def add(op, path, how, to=None):
        if not path or path in ('-', '.', '/dev/null') or path.startswith('/dev/') or path.startswith('-'):
            return
        x = {'op': op, 'path': norm(path), 'how': how}
        if to:
            x['to'] = norm(to)
        if x not in ops:
            ops.append(x)

    for seg, sep in _split_segments(cmd):
        toks, redir, stdin, pre = _parse_segment(seg)
        for fd, op, path in redir:
            if fd in ('1', '&') and path != '/dev/null':
                add('저장', path, '내용 추가(>>)' if op == '>>' else '출력 저장(>)')
        if not toks:
            continue
        name, args = os.path.basename(toks[0]), toks[1:]
        pos = _positional(args, ('-t', '-S', '-m', '-o', '-g', '-n', '-s', '--target-directory', '--suffix'))
        if name in ('rm', 'unlink', 'rmdir'):
            for f in pos:
                add('삭제', f, name + (' -rf' if any(a in ('-rf', '-fr', '-r', '-R') for a in args) else ''))
        elif name == 'shred':
            for f in pos:
                add('삭제', f, 'shred (복구 불가 삭제)')
        elif name == 'mv' and len(pos) >= 2:
            for f in pos[:-1]:
                add('이동', f, 'mv', to=pos[-1])
        elif name in ('cp', 'install') and len(pos) >= 2:
            for f in pos[:-1]:
                add('복사', f, name, to=pos[-1])
        elif name == 'dd':
            src = next((a[3:] for a in args if a.startswith('if=')), None)
            dst = next((a[3:] for a in args if a.startswith('of=')), None)
            if src and dst:
                add('복사', src, 'dd', to=dst)
        elif name == 'touch':
            how = '시각 위조' if (_optval(args, '-r') or _optval(args, '-d') or _optval(args, '-t')) else '생성'
            for f in _positional(args, ('-r', '-d', '-t')):
                add(how, f, 'touch')
        elif name == 'mkdir':
            for f in _positional(args, ('-m',)):
                add('생성', f, 'mkdir (폴더)')
        elif name == 'tee':
            for f in pos:
                add('저장', f, 'tee')
        elif name in ('chmod', 'chown', 'chattr', 'chgrp') and len(args) >= 2:
            mode = args[0]
            for f in [a for a in args[1:] if not a.startswith('-')]:
                add('권한 변경', f, f'{name} {mode}')
        elif name == 'tar' and args:
            flags = args[0].lstrip('-')
            arch = _optval(args, '-f') if '-f' in args else (args[1] if len(args) > 1 and 'f' in flags else None)
            rest = [a for a in args[(2 if arch and arch == args[1] else 1):] if not a.startswith('-') and a != arch]
            if 'c' in flags and arch:
                add('압축 생성', arch, 'tar')
                for f in rest:
                    add('압축에 포함', f, f'tar → {arch}')
            elif 'x' in flags and arch:
                add('압축 해제', arch, 'tar')
        elif name in ('zip', '7z', '7za', 'rar') and pos:
            add('압축 생성', pos[1] if name in ('7z', '7za', 'rar') and len(pos) > 1 else pos[0], name)
        elif name in ('gzip', 'bzip2', 'xz') and pos:
            for f in pos:
                add('압축 생성', f, name)
        elif name in ('unzip', 'gunzip') and pos:
            add('압축 해제', pos[0], name)
        elif name == 'scp':
            if any(re.fullmatch(r'-[A-Za-z]*f', a) for a in args):
                for f in pos:
                    add('외부로 유출', f, 'scp -f (원격에서 가져감)')
            elif any(re.fullmatch(r'-[A-Za-z]*t', a) for a in args):
                for f in pos:
                    add('외부에서 반입', f, 'scp -t (원격에서 올림)')
            else:
                fp = _positional(args, ('-P', '-i', '-o', '-F', '-l', '-S', '-c', '-J'))
                if len(fp) >= 2 and _ARG_REMOTE.match(fp[-1]):
                    for f in fp[:-1]:
                        add('외부로 유출', f, f'scp → {fp[-1].split(":")[0]}')
                elif len(fp) >= 2:
                    add('외부에서 반입', fp[-1], f'scp ← {fp[0].split(":")[0]}')
        elif name == 'rsync':
            fp = _positional(args, ('-e', '--rsh'))
            if len(fp) >= 2 and _ARG_REMOTE.match(fp[-1]):
                for f in fp[:-1]:
                    add('외부로 유출', f, f'rsync → {fp[-1].split(":")[0]}')
        elif name == 'curl':
            up = _optval(args, '-T', '--upload-file')
            if up:
                add('외부로 유출', up, f'curl 업로드 → {_url_host(seg) or "외부"}')
            for m in re.finditer(r'(?:-F|--form)\s+\S*@([^\s;\'"]+)|--data(?:-binary)?\s+@(\S+)', seg):
                add('외부로 유출', m.group(1) or m.group(2), f'curl 전송 → {_url_host(seg) or "외부"}')
            o = _optval(args, '-o', '--output')
            if o:
                add('내려받아 저장', o, f'curl ← {_url_host(seg) or "외부"}')
        elif name == 'wget':
            o = _optval(args, '-O', '--output-document')
            if o:
                add('내려받아 저장', o, f'wget ← {_url_host(seg) or "외부"}')
        elif name in ('nc', 'ncat', 'netcat') and stdin:
            add('외부로 유출', stdin, 'nc 로 전송')
        elif name in ('cat', 'less', 'more', 'head', 'tail', 'vi', 'vim', 'nano', 'strings'):
            for f in pos:
                if any(re.search(rx, f) for rx, _, _ in CRED_FILES) or f == '/etc/passwd':
                    add('열람', f, name)
        elif toks[0].startswith(('./', '/tmp/', '/dev/shm/', '/var/tmp/')) or (toks[0].startswith('/') and HIDDEN_RX.search(toks[0])):
            add('실행', toks[0], '직접 실행')
    return ops


def event_note(e):
    """명령이 아닌 이벤트(로그인, 전송, 덤프 감지 등)가 무슨 뜻인지 설명"""
    k, tags = e.get('kind'), e.get('tags') or []
    if k == 'login_ok':
        if e.get('self_origin'):
            o = e.get('origin')
            base = ('이 서버 안에서 출발한 SSH 접속입니다(출발지 IP 가 이 서버 자신). 그래서 이 IP 는 공격자의 실제 위치가 아닙니다. ')
            if o:
                return base + (f'바로 앞서 세션 {o.get("sid") or "?"}' + (f'({o["ip"]} 에서 들어온 접속)' if o.get('ip') else '')
                               + f' 에서 "{_shorten(o["cmd"], 40)}" 를 실행한 기록이 있어, 그 사람이 서버 안에서 다시 접속한 것으로 보입니다.')
            return base + ('같은 시각에 열려 있던 다른 세션, auditd 의 ssh 실행 기록, 웹셸(웹 서버 로그), 자동화 스크립트(cron)를 확인해 '
                           '실제로 누가 접속을 시작했는지 찾아야 합니다.')
        if '백도어 계정' in tags:
            return '공격자가 만들어 둔 백도어 계정으로 다시 로그인했습니다. 처음 침입 경로를 막아도 이 계정으로 계속 들어올 수 있습니다.'
        if '침입 IP 키 로그인' in tags:
            return ('비밀번호를 대입하던 그 IP 가 이번에는 비밀번호 없이 SSH 키로 들어왔습니다. 공격자가 침입 후 authorized_keys 에 '
                    '자기 키를 심어 두고 그 키로 다시 접속한 것으로 보입니다. 비밀번호를 바꿔도 이 키가 남아 있으면 계속 들어올 수 있습니다.')
        if '무차별 대입 성공' in tags:
            return ('같은 IP 가 여러 계정·비밀번호를 짧은 시간에 연달아 시도하다가 결국 로그인에 성공했습니다. '
                    '비밀번호가 추측(무차별 대입)으로 뚫린 것으로 보입니다. 즉시 비밀번호 변경과 IP 차단이 필요합니다.')
        if e.get('method') == 'publickey':
            return 'SSH 키로 로그인했습니다. 함께 기록된 키 지문(SHA256:…)으로 어떤 키인지 알 수 있습니다. 모르는 키라면 authorized_keys 에 심어진 백도어입니다.'
        return '비밀번호로 SSH 로그인에 성공했습니다.'
    if k == 'login_fail':
        return '비밀번호가 틀려 로그인에 실패했습니다. 같은 IP 에서 짧은 시간에 많이 반복되면 무차별 대입 공격입니다.'
    if k == 'invalid':
        return '서버에 없는 계정 이름으로 접속을 시도했습니다. admin, test, oracle 같은 흔한 이름을 차례로 넣어보는 자동화 공격 도구의 전형적인 흔적입니다.'
    if k == 'btmp':
        return 'btmp 는 실패한 로그인만 따로 모아 두는 기록 파일입니다. 어떤 계정 이름을 몇 번 시도했는지 볼 수 있습니다.'
    if k == 'sftp_req':
        return 'SFTP(파일 전송) 세션을 열었습니다. 이 접속에서는 명령을 친 게 아니라 파일을 주고받았습니다.'
    if k == 'sftp_xfer':
        if '다운로드' in e['msg']:
            return ('"bytes read" 는 서버가 파일을 읽어서 상대에게 보낸 양입니다. 즉 접속한 쪽이 이 파일을 내려받아 간 것(유출)입니다.')
        return '"bytes written" 은 상대가 이 서버에 써 넣은 양입니다. 즉 접속한 쪽이 파일을 올린 것(반입)입니다.'
    if k == 'sftp_op':
        return 'SFTP 로 파일을 지우거나 이름을 바꿨습니다. 가져간 뒤 흔적을 정리한 것일 수 있습니다.' if 'remove' in e['msg'] else 'SFTP 로 파일·폴더를 조작했습니다.'
    if k == 'mysql_dump':
        return ('mysqldump 는 테이블마다 "SELECT /*!40001 SQL_NO_CACHE */ * FROM 테이블" 을 보내 데이터를 꺼냅니다. '
                'DB 로그에 이 패턴이 연속으로 찍혔다는 것은 아래 테이블들이 통째로 복사됐다는 뜻입니다.')
    if k == 'pg_dump':
        return 'pg_dump 는 "COPY 테이블 TO stdout" 으로 테이블 데이터를 통째로 꺼냅니다. 아래 테이블들이 복사됐습니다.'
    if k in ('mysql_outfile', 'pg_copyfile'):
        return 'SQL 로 DB 서버의 파일을 직접 쓰거나 읽었습니다. 데이터를 파일로 빼내거나 웹셸을 심을 때 쓰는 수법입니다.'
    if k in ('mysql_conn', 'pg_conn'):
        return 'DB 서버 접속 기록입니다. 같은 시각의 SSH 세션과 함께 보면 누가 접속했는지 알 수 있습니다.'
    if k == 'acct':
        if 'UID 0' in e['msg']:
            return 'UID 0 은 root 와 같은 최고 권한입니다. root 가 아닌 이름의 UID 0 계정은 대표적인 백도어입니다.'
        return '계정 정보가 바뀌었습니다. 공격 시간대라면 백도어 계정을 만들거나 비밀번호를 바꾼 것일 수 있습니다.'
    if k == 'audit_login':
        return 'auditd 가 남긴 로그인 기록입니다. auth.log 가 지워져도 따로 남아 있을 수 있어 교차 확인에 씁니다.'
    if k == 'wtmp_login':
        return 'wtmp(last 명령이 읽는 파일)에 남은 로그인 기록입니다.'
    if k == 'tamper':
        return ('다른 기록(wtmp, auditd)에는 이 IP 의 로그인이 있는데 auth.log 에는 없습니다. '
                '공격자가 auth.log 에서 자기 흔적을 지웠을 가능성이 있습니다.')
    if k == 'su':
        return 'su 로 다른 계정으로 전환했습니다.'
    if k == 'sudo_fail':
        return 'sudo 비밀번호를 틀렸거나 sudo 권한이 없는 계정입니다. 권한상승을 시도했을 수 있습니다.'
    if k == 'ftp_xfer':
        return 'FTP 로 파일을 주고받았습니다. FTP 기록의 "o"(outgoing)는 서버에서 밖으로 나간 다운로드, "i"는 서버로 들어온 업로드입니다.'
    return None


def annotate(e):
    if e.get('cmd') and e.get('via'):
        if 'DB 히스토리' in (e.get('tags') or []):
            meaning = _sql_meaning(e['cmd'])
            if meaning:
                e['explain'] = {'summary': [f'DB 에서 {meaning}했습니다.'], 'details': [], 'check': []}
        else:
            x = explain_cmd(e['cmd'])
            selfd = [d for d in e.get('dest', []) if d.get('kind') == 'self' and d['proto'] in ('ssh', 'sftp', 'scp', 'rsync')]
            if selfd:
                x['summary'] = [t for t in x['summary'] if not t.startswith('이 서버에서 다른 서버')]
                x['summary'].insert(0, f'이 서버에서 자기 자신({selfd[0]["host"]})으로 다시 SSH 접속했습니다. 이미 들어와 있는 상태에서 '
                                       '다른 계정으로 바꾸거나 제대로 된 셸을 얻으려고 할 때 쓰는 방식이라, 이어지는 로그인 기록의 출발지가 이 서버 자신으로 찍힙니다.')
            if x['summary'] or x['details']:
                e['explain'] = x
    note = event_note(e)
    if note:
        e['note'] = note


# ───────────────────────── 공통 유틸 ─────────────────────────
SYSLOG_RE = re.compile(
    r'^(?:<\d+>)?(?:(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)'
    r'|(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?))'
    r'\s+(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$')
ISO_RE = re.compile(r'^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s*(Z|[+-]\d\d:?\d\d|[+-]\d\d)?$')


def open_text(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')


def rotation_key(path):
    """오래된 로테이션 파일부터: auth.log.4.gz → … → auth.log.1 → auth.log"""
    m = re.search(r'\.(\d+)(?:\.gz)?$', path)
    if m:
        return (0, -int(m.group(1)), '')
    m = re.search(r'-(\d{8})(?:\.gz)?$', path)
    if m:
        return (0, 0, m.group(1))
    return (1, 0, '')


def clean_ip(ip):
    if not ip:
        return None
    ip = ip.strip('[]')
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    return ip


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def human_bytes(n):
    n = float(n)
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024


def tz_from_str(s):
    if not s or s == 'local':
        return dt.datetime.now().astimezone().tzinfo
    if s.upper() in TZ_ABBR:
        return dt.timezone(dt.timedelta(minutes=TZ_ABBR[s.upper()]))
    m = re.fullmatch(r'([+-])(\d{1,2}):?(\d\d)?', s)
    if not m:
        raise argparse.ArgumentTypeError(f'시간대 형식 오류: {s} (예: +09:00, UTC, local)')
    mins = int(m.group(2)) * 60 + int(m.group(3) or 0)
    return dt.timezone(dt.timedelta(minutes=-mins if m.group(1) == '-' else mins))


# auditd 레코드
AUDIT_HDR = re.compile(r'type=(?P<type>\S+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s?(?P<body>.*)$')
KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s\x1d]+)')
HEXRE = re.compile(r'(?:[0-9A-F]{2})+')


def audit_kv(body):
    kv = {}
    for k, v in KV_RE.findall(body):
        if v.startswith("'") and k == 'msg':
            for k2, v2 in KV_RE.findall(v[1:-1]):
                kv.setdefault(k2, v2)
            continue
        kv.setdefault(k, v)
    return kv


def audit_str(v, hexok=True):
    if v is None:
        return None
    if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
        return v[1:-1]
    if hexok and HEXRE.fullmatch(v):
        try:
            return bytes.fromhex(v).decode('utf-8', 'replace').replace('\x00', ' ').strip()
        except ValueError:
            pass
    return v


def shell_join(args):
    out = []
    for a in args:
        if a == '' or re.search(r'[\s"\'$`\\|&;<>()*?]', a):
            out.append("'" + a.replace("'", "'\\''") + "'")
        else:
            out.append(a)
    return ' '.join(out)


# ───────────────────────── 분석기 ─────────────────────────
class Analyzer:
    def __init__(self, root, tz, year=None, audit_all=False, use_journal=True, since=None, server_ips=()):
        self.root = os.path.abspath(root)
        self.tz = tz
        self.year = year
        self.audit_all = audit_all
        self.use_journal = use_journal
        self.since = since
        self.events = []
        self.sources = []
        self.notes = []
        self.hosts = Counter()
        self.seq = 0
        self.uid_names = {}
        self.uid0_alias = set()
        self.histories = []
        self.known_hosts = []
        self.server_ips = {x.strip() for x in server_ips if x and x.strip()}
        self.server_ips_auto = set()
        self.has_auth = False

    # ── 기본 ──
    def rel(self, path):
        r = os.path.relpath(path, self.root).replace('\\', '/')
        return '/' + r if not r.startswith('/') else r

    def paths(self, *patterns):
        out = set()
        for p in patterns:
            for x in glob.glob(os.path.join(self.root, p)):
                if os.path.isfile(x):
                    out.add(x)
        base = lambda x: re.sub(r'(?:\.\d+|-\d{8})?(?:\.gz)?$', '', x)
        return sorted(out, key=lambda x: (base(x), rotation_key(x)))

    def add(self, ts, cat, sev, msg, **kw):
        self.seq += 1
        e = {'ts': ts, 'cat': cat, 'sev': sev, 'msg': msg, 'seq': self.seq}
        for k, v in kw.items():
            if v is not None and v != '' and v != []:
                e[k] = v
        self.events.append(e)
        return e

    def source(self, path, kind, before):
        self.sources.append({'path': path, 'kind': kind, 'events': len(self.events) - before})

    def safe_open(self, path):
        try:
            return open_text(path)
        except PermissionError:
            self.notes.append(f'읽기 권한 없음: {self.rel(path)} — sudo 로 실행하세요')
        except OSError as ex:
            self.notes.append(f'열기 실패: {self.rel(path)} ({ex})')
        return None

    def ts_bsd(self, s, ref_epoch):
        try:
            mon, day, hms = s.split()
            h, mi, se = map(int, hms.split(':'))
            ref = dt.datetime.fromtimestamp(ref_epoch, self.tz)
            year = self.year or ref.year
            d = dt.datetime(year, MONTHS[mon], int(day), h, mi, se, tzinfo=self.tz)
            if not self.year and d.timestamp() > ref_epoch + 2 * 86400:
                d = d.replace(year=year - 1)
            return d.timestamp()
        except (ValueError, KeyError):
            return None

    def ts_iso(self, s, tz=None):
        m = ISO_RE.match(s.strip())
        if not m:
            return None
        y, mo, d, h, mi, se, frac, off = m.groups()
        if off is None:
            tzinfo = tz or self.tz
        elif off == 'Z':
            tzinfo = dt.timezone.utc
        else:
            digits = off[1:].replace(':', '')
            mins = int(digits[:2]) * 60 + int(digits[2:4] or 0)
            tzinfo = dt.timezone(dt.timedelta(minutes=-mins if off[0] == '-' else mins))
        us = int((frac or '0')[:6].ljust(6, '0'))
        try:
            return dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), us, tzinfo=tzinfo).timestamp()
        except ValueError:
            return None

    def run(self):
        self.load_passwd()
        self.scan_auth()
        self.scan_audit()
        self.scan_history()
        self.scan_wtmp()
        self.scan_mysql()
        self.scan_postgres()
        self.scan_ftp()
        self.scan_known_hosts()
        if self.since:
            self.events = [e for e in self.events if e['ts'] is None or e['ts'] >= self.since]
        return self.correlate()

    def load_passwd(self):
        p = os.path.join(self.root, 'etc/passwd')
        if not os.path.isfile(p):
            return
        f = self.safe_open(p)
        if not f:
            return
        with f:
            for line in f:
                parts = line.split(':')
                if len(parts) >= 3:
                    self.uid_names.setdefault(parts[2], parts[0])
                    if parts[2] == '0' and parts[0] != 'root':
                        self.uid0_alias.add(parts[0])
                        self.notes.append(f'/etc/passwd 에 UID 0 계정 존재: {parts[0]} (백도어 계정 의심)')

    def uname(self, uid):
        if uid is None or uid in UNSET_AUID:
            return None
        return self.uid_names.get(uid, f'uid={uid}')

    # ── SSH / 인증 로그 ──
    def scan_auth(self):
        files = self.paths('var/log/auth.log*', 'var/log/secure*')
        self.sftp_pids = {}
        for p in files:
            f = self.safe_open(p)
            if not f:
                continue
            self.has_auth = True
            before = len(self.events)
            with f:
                self.auth_lines(f, os.path.getmtime(p), self.rel(p))
            self.source(self.rel(p), 'SSH/계정', before)
        if not self.has_auth and self.root == os.path.abspath('/') and self.use_journal and shutil.which('journalctl'):
            cmd = ['journalctl', '-o', 'short-iso', '--no-pager', '-q']
            for t in ('sshd', 'sudo', 'su', 'useradd', 'usermod', 'userdel', 'passwd', 'chpasswd',
                      'groupadd', 'internal-sftp', 'sftp-server'):
                cmd += ['-t', t]
            if self.since:
                cmd += ['--since', dt.datetime.fromtimestamp(self.since).strftime('%Y-%m-%d %H:%M:%S')]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=300).stdout
                before = len(self.events)
                self.auth_lines(out.splitlines(), time.time(), 'journalctl')
                self.has_auth = True
                self.source('journalctl (sshd, sudo, su, useradd …)', 'SSH/계정', before)
            except (OSError, subprocess.SubprocessError) as ex:
                self.notes.append(f'journalctl 실행 실패: {ex}')
        if not self.has_auth:
            self.notes.append('auth.log / secure 로그가 없습니다. 삭제됐거나 journald 만 쓰는 시스템일 수 있습니다.')

    SSH_RX = [
        ('login_ok', re.compile(r'^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2(?:: (?P<key>.+))?)?')),
        ('login_fail', re.compile(r'^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)')),
        ('invalid', re.compile(r'^Invalid user (?P<user>\S*) from (?P<ip>\S+)')),
        ('sess_open', re.compile(r'^pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)')),
        ('sess_close', re.compile(r'^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)')),
        ('disconnect', re.compile(r'^(?:Disconnected from|Received disconnect from|Connection closed by|Connection reset by) '
                                  r'(?:(?:authenticating|invalid) )?(?:user (?P<user>\S+) )?(?P<ip>[0-9a-fA-F:.]+)')),
        ('sftp_req', re.compile(r'^subsystem request for (?P<sub>\S+)(?: by user (?P<user>\S+))?')),
        ('maxauth', re.compile(r'(?:maximum authentication attempts exceeded for|PAM \d+ more authentication failures;)'
                               r'.*?(?:user[= ](?P<user>\S+))?.*?(?:from |rhost=)(?P<ip>[0-9a-fA-F:.]+)')),
    ]
    SUDO_RX = re.compile(r'^\s*(?P<user>\S+)\s*:\s*(?:(?P<fail>[^;]*?)\s*;\s*)?TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>.*?)\s*;'
                         r'\s*USER=(?P<runas>\S+)\s*;(?:.*?;)?\s*COMMAND=(?P<cmd>.*)$')
    SFTP_SESS = re.compile(r'^session (?P<oc>opened|closed) for local user (?P<user>\S+) from \[(?P<ip>[^\]]+)\]')
    SFTP_CLOSE = re.compile(r'^close "(?P<path>.*)" bytes read (?P<r>\d+) written (?P<w>\d+)')
    SFTP_OP = re.compile(r'^(?P<op>remove|rename|mkdir|rmdir|symlink)(?: name)? "(?P<path>[^"]*)"(?: "(?P<to>[^"]*)")?')

    def auth_lines(self, lines, ref, src):
        for i, line in enumerate(lines, 1):
            line = line.rstrip('\n')
            m = SYSLOG_RE.match(line)
            if not m:
                continue
            ts = self.ts_bsd(m['bsd'], ref) if m['bsd'] else self.ts_iso(m['iso'])
            if ts is None:
                continue
            host, prog, pid, msg = m['host'], m['prog'], m['pid'], m['msg']
            self.hosts[host] += 1
            base = dict(host=host, src=src, line=i, raw=line, pid=pid)
            if prog == 'sshd':
                self.sshd_line(ts, msg, base)
            elif prog == 'sudo':
                self.sudo_line(ts, msg, base)
            elif prog == 'su' or msg.startswith('pam_unix(su'):
                self.su_line(ts, msg, base)
            elif prog in ('useradd', 'usermod', 'userdel', 'groupadd', 'passwd', 'chpasswd', 'chage', 'gpasswd'):
                self.acct_line(ts, prog, msg, base)
            elif prog in ('internal-sftp', 'sftp-server'):
                self.sftp_line(ts, msg, base)

    def sshd_line(self, ts, msg, base):
        m = re.match(r'^(?:Connection from \S+ port \d+ on (\S+) port \d+|Server listening on (\S+) port \d+)', msg)
        if m:
            ip = clean_ip(m[1] or m[2])
            if ip and ip not in ('0.0.0.0', '::') and not ip.startswith('127.') and ip != '::1':
                self.server_ips_auto.add(ip)
            return
        for kind, rx in self.SSH_RX:
            m = rx.match(msg) if kind != 'maxauth' else rx.search(msg)
            if not m:
                continue
            g = m.groupdict()
            ip = clean_ip(g.get('ip'))
            user = g.get('user')
            if kind == 'login_ok':
                sev = 'med' if is_private(ip) else 'high'
                self.add(ts, 'auth', sev, f'SSH 로그인 성공 ({g["method"]})', kind=kind, user=user, ip=ip,
                         method=g['method'], detail=g.get('key'), **base)
            elif kind == 'login_fail':
                inv = ' — 존재하지 않는 계정' if g.get('invalid') else ''
                self.add(ts, 'auth', 'low', f'SSH 로그인 실패 ({g["method"]}){inv}', kind=kind, user=user, ip=ip, **base)
            elif kind == 'invalid':
                self.add(ts, 'auth', 'info', '존재하지 않는 계정으로 접속 시도', kind=kind, user=user, ip=ip, **base)
            elif kind == 'maxauth':
                self.add(ts, 'auth', 'low', '인증 시도 횟수 초과', kind=kind, user=user, ip=ip, **base)
            elif kind == 'sess_open':
                self.add(ts, 'session', 'info', 'SSH 세션 시작', kind=kind, user=user, **base)
            elif kind == 'sess_close':
                self.add(ts, 'session', 'info', 'SSH 세션 종료', kind=kind, user=user, **base)
            elif kind == 'disconnect':
                self.add(ts, 'session', 'info', '연결 종료', kind=kind, user=user, ip=ip, **base)
            elif kind == 'sftp_req':
                self.add(ts, 'transfer', 'med', f'SSH 서브시스템 요청: {g["sub"]} (파일 전송 세션)', kind=kind, user=user, **base)
            return

    def sudo_line(self, ts, msg, base):
        m = self.SUDO_RX.match(msg)
        if not m:
            return
        if m['fail']:
            self.add(ts, 'privesc', 'med', f'sudo 실패: {m["fail"]}', kind='sudo_fail', user=m['user'],
                     cmd=m['cmd'], tags=['sudo'], **base)
            return
        e = self.cmd_event(ts, m['cmd'], m['user'], via='sudo', cwd=m['pwd'], runas=m['runas'], **base)
        if e and m['runas'] != 'root':
            e['tags'].append(f'실행계정={m["runas"]}')

    def su_line(self, ts, msg, base):
        m = re.search(r'session opened for user (\S+?)(?:\(uid=\d+\))? by (\S+?)(?:\(uid=\d+\))?$', msg)
        if m:
            self.add(ts, 'privesc', 'med', f'su 로 계정 전환: {m[2]} → {m[1]}', kind='su', user=m[2], **base)
            return
        if 'FAILED' in msg or 'authentication failure' in msg:
            self.add(ts, 'privesc', 'low', 'su 실패', kind='su_fail', **base)

    def acct_line(self, ts, prog, msg, base):
        if prog == 'useradd' and 'new user' in msg:
            m = re.search(r'name=([^,\s]+).*?UID=(\d+)', msg)
            name, uid = (m[1], m[2]) if m else ('?', '?')
            if uid == '0':
                self.add(ts, 'persist', 'crit', f'UID 0 백도어 계정 생성: {name}', kind='acct', target=name, **base)
            else:
                self.add(ts, 'persist', 'high', f'계정 생성: {name} (UID {uid})', kind='acct', target=name, **base)
        elif 'password changed' in msg:
            m = re.search(r'password changed for (\S+)', msg)
            self.add(ts, 'persist', 'high', f'비밀번호 변경: {m[1] if m else "?"}', kind='acct', **base)
        elif prog in ('usermod', 'gpasswd') and re.search(r'add .* to (?:group|shadow group) .*(sudo|wheel|root|admin)', msg):
            self.add(ts, 'persist', 'crit', f'관리자 그룹 추가: {msg}', kind='acct', **base)
        elif prog in ('usermod', 'userdel', 'groupadd', 'chage'):
            self.add(ts, 'persist', 'med', f'{prog}: {msg}', kind='acct', **base)

    def sftp_line(self, ts, msg, base):
        pid = base['pid']
        m = self.SFTP_SESS.match(msg)
        if m:
            if m['oc'] == 'opened':
                self.sftp_pids[pid] = (m['user'], clean_ip(m['ip']))
            return
        user, ip = self.sftp_pids.get(pid, (None, None))
        m = self.SFTP_CLOSE.match(msg)
        if m:
            r, w = int(m['r']), int(m['w'])
            if r > 0:
                self.add(ts, 'transfer', 'crit', f'SFTP 다운로드 (서버 → 외부 유출) {human_bytes(r)}', kind='sftp_xfer',
                         user=user, ip=ip, path=m['path'], bytes=r, cmd=m['path'], **base)
            if w > 0:
                self.add(ts, 'transfer', 'high', f'SFTP 업로드 (외부 → 서버 반입) {human_bytes(w)}', kind='sftp_xfer',
                         user=user, ip=ip, path=m['path'], bytes=w, cmd=m['path'], **base)
            return
        m = self.SFTP_OP.match(msg)
        if m:
            target = m['path'] + (f' → {m["to"]}' if m['to'] else '')
            self.add(ts, 'transfer', 'med', f'SFTP {m["op"]}', kind='sftp_op', user=user, ip=ip, cmd=target, **base)

    # ── 명령 이벤트 공통 ──
    VIA = {'history': '셸 히스토리', 'audit': 'auditd', 'sudo': 'sudo'}

    def cmd_event(self, ts, cmd, user, via, **kw):
        cmd = cmd.strip()
        if not cmd:
            return None
        cat, sev, labels = classify(cmd)
        msg = labels[0] if labels else '명령 실행'
        if len(labels) > 1 and labels[0] == '파일 전송':
            msg = labels[1]
        return self.add(ts, cat, sev, msg, cmd=cmd, user=user, via=via,
                        tags=[self.VIA[via]] + [l for l in labels if l != msg], **kw)

    # ── auditd ──
    def scan_audit(self):
        noise = {'unix_chkpwd', 'sshd', 'run-parts', 'dircolors', 'lesspipe', 'basename', 'dirname',
                 'locale-check', 'tput', 'groups', 'update-motd', '50-motd-news', 'landscape-sysinfo'}
        for p in self.paths('var/log/audit/audit.log*'):
            f = self.safe_open(p)
            if not f:
                continue
            before = len(self.events)
            src = self.rel(p)
            recs = {}
            with f:
                for i, line in enumerate(f, 1):
                    m = AUDIT_HDR.search(line)
                    if not m:
                        continue
                    key = (m['ts'], m['serial'])
                    r = recs.get(key)
                    if r is None:
                        r = recs[key] = {'ts': float(m['ts']), 'line': i, 'raw': [], 'types': {}}
                    r['raw'].append(line.rstrip('\n'))
                    r['types'].setdefault(m['type'], audit_kv(m['body']))
            for r in recs.values():
                t = r['types']
                if 'EXECVE' in t:
                    sc = t.get('SYSCALL', {})
                    auid = sc.get('auid')
                    if (auid is None or auid in UNSET_AUID) and not self.audit_all:
                        continue
                    ex = t['EXECVE']
                    try:
                        argc = int(ex.get('argc', '0'))
                    except ValueError:
                        argc = 0
                    args = [audit_str(ex[f'a{n}']) for n in range(argc) if f'a{n}' in ex]
                    if not args:
                        continue
                    if os.path.basename(args[0]) in noise:
                        continue
                    user = audit_str(sc.get('AUID'), False) or self.uname(auid) or f'uid={sc.get("uid")}'
                    real = self.uname(sc.get('uid'))
                    e = self.cmd_event(r['ts'], shell_join(args), user, via='audit', src=src, line=r['line'],
                                       raw='\n'.join(r['raw']), ses=sc.get('ses'), pid=sc.get('pid'),
                                       cwd=audit_str(t.get('CWD', {}).get('cwd')), argv0=args[0],
                                       exe=audit_str(sc.get('exe'), False))
                    if e and real and real != user:
                        e['tags'].append(f'실행계정={real}')
                elif 'USER_LOGIN' in t:
                    k = t['USER_LOGIN']
                    ip = clean_ip(audit_str(k.get('addr'), False))
                    if not ip or ip == '?':
                        continue
                    user = audit_str(k.get('acct')) or self.uname(k.get('auid')) or self.uname(k.get('id'))
                    res = audit_str(k.get('res'), False)
                    if res == 'success':
                        self.add(r['ts'], 'session', 'info', 'audit 로그인 기록', kind='audit_login', user=user, ip=ip,
                                 ses=k.get('ses'), pid=k.get('pid'), src=src, line=r['line'], raw='\n'.join(r['raw']))
                    else:
                        self.add(r['ts'], 'auth', 'low', 'audit 로그인 실패 기록', kind='audit_fail', user=user, ip=ip,
                                 src=src, line=r['line'], raw='\n'.join(r['raw']))
            self.source(src, 'auditd', before)

    # ── 셸/DB 클라이언트 히스토리 ──
    def scan_history(self):
        pats = []
        for home in ('root', 'home/*', 'var/lib/*', 'srv/*'):
            for n in ('.bash_history', '.zsh_history', '.sh_history', '.ash_history', '.history',
                      '.mysql_history', '.psql_history'):
                pats.append(f'{home}/{n}')
        for p in self.paths(*pats):
            rp = self.rel(p)
            parts = rp.strip('/').split('/')
            user = 'root' if parts[0] == 'root' else parts[1] if len(parts) > 2 else parts[0]
            if parts[0] == 'var':  # /var/lib/postgresql 등 서비스 계정
                user = {'postgresql': 'postgres', 'pgsql': 'postgres'}.get(parts[2], parts[2])
            f = self.safe_open(p)
            if not f:
                continue
            before = len(self.events)
            dbhist = p.endswith(('.mysql_history', '.psql_history'))
            entries = []
            with f:
                pending = None
                for i, line in enumerate(f, 1):
                    line = line.rstrip('\n')
                    s = line.strip()
                    if not s:
                        continue
                    mt = re.fullmatch(r'#(\d{9,11})', s)
                    if mt:
                        pending = int(mt.group(1))
                        continue
                    mz = re.match(r'^: (\d{9,11}):\d+;(.*)$', line)
                    ts, cmd = (int(mz.group(1)), mz.group(2)) if mz else (pending, line)
                    pending = None
                    if dbhist:
                        cmd = cmd.replace('\\040', ' ')
                        self.db_history(ts, cmd, user, rp, i, line)
                    else:
                        self.cmd_event(ts, cmd, user, via='history', src=rp, line=i, raw=line)
                    if len(entries) < 20000:
                        entries.append([i, ts, cmd])
            try:
                size, mtime = os.path.getsize(p), os.path.getmtime(p)
            except OSError:
                size, mtime = None, None
            self.histories.append({'path': rp, 'user': user, 'db': dbhist, 'entries': entries, 'size': size, 'mtime': mtime,
                                   'with_ts': sum(1 for e in entries if e[1] is not None)})
            self.source(rp, 'DB 클라이언트 기록' if dbhist else '셸 히스토리', before)

    def db_history(self, ts, sql, user, src, i, raw):
        if re.search(r'(?i)into\s+(?:out|dump)file|\bcopy\b.+\bto\b|load_file\s*\(|pg_read_file', sql):
            sev, msg = 'crit', 'SQL 로 파일 쓰기/읽기 (덤프 의심)'
        elif re.search(r'(?i)select\s+\*\s+from\s+\S*(user|member|customer|account|pay|card|order)', sql):
            sev, msg = 'med', '민감 테이블 조회'
        elif re.search(r'(?i)\b(drop|truncate|delete\s+from|grant|create\s+user|alter\s+user)\b', sql):
            sev, msg = 'high', '파괴적/권한 변경 SQL'
        else:
            sev, msg = 'info', 'DB 클라이언트 명령'
        self.add(ts, 'db', sev, msg, cmd=sql, user=user, via='history', src=src, line=i, raw=raw, tags=['DB 히스토리'])

    # ── wtmp / btmp ──
    UTMP = struct.Struct('<hxxi32s4s32s256shhiii4i20s')

    def scan_wtmp(self):
        for p in self.paths('var/log/wtmp*', 'var/log/btmp*'):
            rp = self.rel(p)
            try:
                data = gzip.open(p, 'rb').read() if p.endswith('.gz') else open(p, 'rb').read()
            except PermissionError:
                self.notes.append(f'읽기 권한 없음: {rp} — sudo 로 실행하세요')
                continue
            except OSError:
                continue
            if len(data) % self.UTMP.size:
                self.notes.append(f'{rp} 크기가 레코드 단위({self.UTMP.size}B)로 나누어지지 않음 — 변조/손상 의심')
            before = len(self.events)
            is_btmp = 'btmp' in os.path.basename(p)
            agg = {}
            for n in range(len(data) // self.UTMP.size):
                rec = self.UTMP.unpack_from(data, n * self.UTMP.size)
                typ, pid, tty, user, host, sec = rec[0], rec[1], rec[2], rec[4], rec[5], rec[9]
                dec = lambda b: b.split(b'\0', 1)[0].decode('utf-8', 'replace')
                tty, user, host = dec(tty), dec(user), dec(host)
                ip = clean_ip(host) if host and not host.startswith(':') else None
                if is_btmp:
                    if not ip:
                        continue
                    a = agg.setdefault((ip, user), {'n': 0, 'first': sec, 'last': sec, 'rec': n})
                    a['n'] += 1
                    a['first'], a['last'] = min(a['first'], sec), max(a['last'], sec)
                elif typ == 7 and user:
                    self.add(sec, 'session', 'info', f'로그인 기록 (wtmp, {tty})', kind='wtmp_login', user=user, ip=ip,
                             tty=tty, pid=str(pid), src=rp, line=n + 1)
                elif typ == 8:
                    self.add(sec, 'session', 'info', f'로그아웃 기록 (wtmp, {tty})', kind='wtmp_logout', tty=tty,
                             src=rp, line=n + 1, hidden=True)
            per_ip = {}
            for (ip, user), a in agg.items():
                b = per_ip.setdefault(ip, {'n': 0, 'first': a['first'], 'last': a['last'], 'rec': a['rec'], 'users': Counter()})
                b['n'] += a['n']
                b['users'][user] += a['n']
                b['first'], b['last'] = min(b['first'], a['first']), max(b['last'], a['last'])
                b['rec'] = min(b['rec'], a['rec'])
            for ip, b in per_ip.items():
                users = b['users'].most_common()
                self.add(b['first'], 'auth', 'med' if b['n'] >= 10 else 'low',
                         f'로그인 실패 {b["n"]}회 (btmp, 계정 {len(users)}개)', kind='btmp', ip=ip, count=b['n'],
                         users=users, cmd=', '.join(f'{u}({n})' for u, n in users[:15]), until=b['last'],
                         src=rp, line=b['rec'] + 1)
            self.source(rp, 'btmp' if is_btmp else 'wtmp', before)

    # ── MySQL general log ──
    MYSQL_RX = re.compile(r'^(?:(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?|\d{6}\s+\d{1,2}:\d\d:\d\d)\s+|\s+)'
                          r'(?P<id>\d+)\s(?P<cmd>Connect|Query|Quit|Init DB|Field List|Execute|Prepare)\s*(?P<arg>.*)$')

    def scan_mysql(self):
        files = self.paths('var/log/mysql/*.log*', 'var/log/mysql*.log*', 'var/log/mariadb/*.log*', 'var/lib/mysql/*.log')
        for p in files:
            f = self.safe_open(p)
            if not f:
                continue
            rp = self.rel(p)
            before = len(self.events)
            conns = {}
            cur_ts = None

            def flush(cid):
                c = conns.pop(cid, None)
                if not c or not (c['tables'] or c['snapshot']):
                    return
                tabs = c['tables']
                listed = ', '.join(tabs[:12]) + (f' 외 {len(tabs) - 12}개' if len(tabs) > 12 else '')
                self.add(c['dump_ts'] or c['ts'], 'db', 'crit',
                         f'mysqldump 덤프 패턴 감지 — 테이블 {len(tabs)}개' + (f' ({", ".join(c["dbs"])})' if c['dbs'] else ''),
                         kind='mysql_dump', user=c['user'], ip=c['ip'], cmd=listed, src=rp, line=c['line'],
                         raw='\n'.join(c['raw'][:40]), tags=['MySQL general log', f'conn {cid}'])

            with f:
                for i, line in enumerate(f, 1):
                    m = self.MYSQL_RX.match(line.rstrip('\n'))
                    if not m:
                        continue
                    if m['ts']:
                        if 'T' in m['ts']:
                            cur_ts = self.ts_iso(m['ts'], tz=dt.timezone.utc)
                        else:
                            try:
                                cur_ts = dt.datetime.strptime(re.sub(r'\s+', ' ', m['ts']), '%y%m%d %H:%M:%S') \
                                    .replace(tzinfo=self.tz).timestamp()
                            except ValueError:
                                pass
                    cid, cmd, arg = m['id'], m['cmd'], m['arg'].strip()
                    raw = line.rstrip('\n')
                    if cmd == 'Connect':
                        flush(cid)
                        mc = re.match(r"(?P<u>[^@\s]+)@(?P<h>\S+)(?: on (?P<db>\S*))?", arg)
                        if 'Access denied' in arg:
                            ma = re.search(r"user '([^']*)'@'([^']*)'", arg)
                            self.add(cur_ts, 'db', 'low', 'MySQL 접속 거부', kind='mysql_denied',
                                     user=ma[1] if ma else None, ip=clean_ip(ma[2]) if ma else None,
                                     src=rp, line=i, raw=raw, tags=['MySQL general log'])
                            continue
                        u, h = (mc['u'], mc['h']) if mc else (None, None)
                        ip = None if h in (None, 'localhost', '127.0.0.1', '::1') else clean_ip(h)
                        conns[cid] = {'user': u, 'ip': ip, 'ts': cur_ts, 'line': i, 'tables': [], 'dbs': [],
                                      'snapshot': False, 'dump_ts': None, 'raw': [raw]}
                        self.add(cur_ts, 'db', 'low' if ip else 'info', f'MySQL 접속: {u}@{h}', kind='mysql_conn',
                                 user=u, ip=ip, src=rp, line=i, raw=raw, tags=['MySQL general log'])
                        continue
                    c = conns.setdefault(cid, {'user': None, 'ip': None, 'ts': cur_ts, 'line': i, 'tables': [], 'dbs': [],
                                               'snapshot': False, 'dump_ts': None, 'raw': []})
                    if len(c['raw']) < 200:
                        c['raw'].append(raw)
                    if cmd == 'Quit':
                        flush(cid)
                    elif cmd == 'Init DB':
                        c['dbs'].append(arg)
                    elif cmd == 'Query':
                        if re.search(r'SQL_NO_CACHE', arg):
                            mt = re.search(r'FROM\s+`?([\w$]+)`?(?:\.`?([\w$]+)`?)?', arg, re.I)
                            if mt:
                                c['tables'].append(mt[2] or mt[1])
                                c['dump_ts'] = c['dump_ts'] or cur_ts
                        elif re.search(r'WITH CONSISTENT SNAPSHOT|SET @@SQL_MODE\s*=\s*\'\'', arg):
                            c['snapshot'] = True
                            c['dump_ts'] = c['dump_ts'] or cur_ts
                        if re.search(r'(?i)into\s+(?:out|dump)file|load_file\s*\(', arg):
                            self.add(cur_ts, 'db', 'crit', 'SQL 로 서버 파일 쓰기/읽기 (INTO OUTFILE / LOAD_FILE)',
                                     kind='mysql_outfile', user=c['user'], ip=c['ip'], cmd=arg, src=rp, line=i, raw=raw,
                                     tags=['MySQL general log'])
            for cid in list(conns):
                flush(cid)
            if len(self.events) > before:
                self.source(rp, 'MySQL', before)

    # ── PostgreSQL ──
    PG_RX = re.compile(r'^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)(?:\s+(?P<tz>[A-Za-z]{2,5}|[+-]\d\d(?::?\d\d)?))?'
                       r'\s+\[(?P<pid>\d+)\](?:-\d+)?\s*(?:(?P<user>[\w.\-\[\]]*)@(?P<db>[\w.\-\[\]]*)\s+)?'
                       r'(?P<lvl>LOG|STATEMENT|ERROR|FATAL|WARNING|DETAIL|HINT|PANIC):\s+(?P<msg>.*)$')

    def scan_postgres(self):
        files = self.paths('var/log/postgresql/*.log*', 'var/lib/pgsql/*/data/log/*.log', 'var/lib/pgsql/data/log/*.log',
                           'var/lib/postgresql/*/main/log/*.log', 'var/lib/pgsql/*/data/pg_log/*.log')
        for p in files:
            f = self.safe_open(p)
            if not f:
                continue
            rp = self.rel(p)
            before = len(self.events)
            conns = {}

            def flush(pid):
                c = conns.pop(pid, None)
                if not c or not (c['tables'] or c['dumpapp']):
                    return
                tabs = c['tables']
                what = f'{c["app"]} 실행' if c['dumpapp'] else 'COPY TO 대량 추출'
                self.add(c['dump_ts'] or c['ts'], 'db', 'crit', f'PostgreSQL 덤프 감지 — {what}, 테이블 {len(tabs)}개'
                         + (f' (DB {c["db"]})' if c['db'] else ''), kind='pg_dump', user=c['user'], ip=c['ip'],
                         cmd=', '.join(tabs[:12]) or None, src=rp, line=c['line'], raw='\n'.join(c['raw'][:40]),
                         tags=['PostgreSQL 로그', f'pid {pid}'])

            with f:
                for i, line in enumerate(f, 1):
                    raw = line.rstrip('\n')
                    m = self.PG_RX.match(raw)
                    if not m:
                        continue
                    tz = None
                    if m['tz']:
                        if m['tz'].upper() in TZ_ABBR:
                            tz = dt.timezone(dt.timedelta(minutes=TZ_ABBR[m['tz'].upper()]))
                        elif m['tz'][0] in '+-':
                            tz = tz_from_str(m['tz'])
                    ts = self.ts_iso(m['ts'], tz=tz)
                    pid, msg = m['pid'], m['msg']
                    c = conns.get(pid)
                    if msg.startswith('connection received:'):
                        mh = re.search(r'host=(\S+)', msg)
                        h = mh[1] if mh else None
                        conns[pid] = {'ip': None if h in (None, '[local]', '127.0.0.1', '::1') else clean_ip(h),
                                      'user': None, 'db': None, 'app': None, 'dumpapp': False, 'tables': [],
                                      'ts': ts, 'dump_ts': None, 'line': i, 'raw': [raw]}
                        continue
                    if c is None:
                        c = conns[pid] = {'ip': None, 'user': m['user'], 'db': m['db'], 'app': None, 'dumpapp': False,
                                          'tables': [], 'ts': ts, 'dump_ts': None, 'line': i, 'raw': []}
                    if len(c['raw']) < 200:
                        c['raw'].append(raw)
                    if msg.startswith('connection authorized:'):
                        kv = dict(re.findall(r'(\w+)=(\S+)', msg))
                        c.update(user=kv.get('user'), db=kv.get('database'), app=kv.get('application_name'))
                        if c['app'] in ('pg_dump', 'pg_dumpall', 'pg_basebackup'):
                            c['dumpapp'] = True
                            c['dump_ts'] = ts
                        self.add(ts, 'db', 'low' if c['ip'] else 'info',
                                 f'PostgreSQL 접속: {c["user"]} → {c["db"]}' + (f' ({c["app"]})' if c['app'] else ''),
                                 kind='pg_conn', user=c['user'], ip=c['ip'], src=rp, line=i, raw=raw, tags=['PostgreSQL 로그'])
                    elif m['lvl'] == 'FATAL' and 'authentication failed' in msg:
                        mu = re.search(r'user "([^"]+)"', msg)
                        self.add(ts, 'db', 'low', 'PostgreSQL 인증 실패', kind='pg_fail', user=mu[1] if mu else None,
                                 ip=c['ip'], src=rp, line=i, raw=raw, tags=['PostgreSQL 로그'])
                    elif re.search(r'(?i)\bcopy\b', msg):
                        mt = re.search(r'(?i)copy\s+(?:\()?\s*([\w."]+)', msg)
                        if re.search(r"(?i)\bto\s+(?:'|program)", msg):
                            self.add(ts, 'db', 'crit', 'COPY TO 로 서버 파일 쓰기/명령 실행', kind='pg_copyfile',
                                     user=c['user'], ip=c['ip'], cmd=msg, src=rp, line=i, raw=raw, tags=['PostgreSQL 로그'])
                        elif re.search(r'(?i)\bto\s+stdout', msg) and mt:
                            c['tables'].append(mt[1])
                            c['dump_ts'] = c['dump_ts'] or ts
                    elif msg.startswith('disconnection:'):
                        flush(pid)
            for pid in list(conns):
                flush(pid)
            if len(self.events) > before:
                self.source(rp, 'PostgreSQL', before)

    # ── FTP ──
    def scan_ftp(self):
        for p in self.paths('var/log/xferlog*', 'var/log/vsftpd.log*', 'var/log/proftpd/xferlog*'):
            f = self.safe_open(p)
            if not f:
                continue
            rp = self.rel(p)
            before = len(self.events)
            with f:
                for i, line in enumerate(f, 1):
                    raw = line.rstrip('\n')
                    toks = raw.split()
                    mv = re.search(r'\[(?P<user>[^\]]+)\] (?P<res>OK|FAIL) (?P<op>DOWNLOAD|UPLOAD|LOGIN|DELETE|RENAME|MKDIR):'
                                   r' Client "(?P<ip>[^"]+)"(?:, "(?P<path>[^"]*)")?(?:, (?P<b>\d+) bytes)?', raw)
                    if mv and len(toks) >= 5:
                        ts = self.ftp_ts(toks[:5])
                        ip, op = clean_ip(mv['ip']), mv['op']
                        if op == 'LOGIN':
                            self.add(ts, 'auth', 'med' if mv['res'] == 'OK' else 'low', f'FTP 로그인 {mv["res"]}',
                                     kind='ftp_login', user=mv['user'], ip=ip, src=rp, line=i, raw=raw)
                        elif mv['res'] == 'OK':
                            down = op == 'DOWNLOAD'
                            size = f' {human_bytes(mv["b"])}' if mv['b'] else ''
                            self.add(ts, 'transfer', 'crit' if down else 'high',
                                     ('FTP 다운로드 (서버 → 외부 유출)' if down else f'FTP {op}') + size, kind='ftp_xfer',
                                     user=mv['user'], ip=ip, cmd=mv['path'], src=rp, line=i, raw=raw)
                    elif len(toks) >= 17 and toks[0] in ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'):
                        # xferlog: date(5) time host bytes file type action dir mode user svc auth authuser status
                        ts = self.ftp_ts(toks[:5])
                        ip, size, direction, user = clean_ip(toks[6]), toks[7], toks[-9], toks[-5]
                        path = ' '.join(toks[8:-9])
                        down = direction == 'o'
                        self.add(ts, 'transfer', 'crit' if down else 'high',
                                 ('FTP 다운로드 (서버 → 외부 유출) ' if down else 'FTP 업로드 (외부 → 서버 반입) ')
                                 + human_bytes(size), kind='ftp_xfer', user=user, ip=ip, cmd=path, src=rp, line=i, raw=raw)
            self.source(rp, 'FTP', before)

    def scan_known_hosts(self):
        for p in self.paths('root/.ssh/known_hosts*', 'home/*/.ssh/known_hosts*'):
            rp = self.rel(p)
            parts = rp.strip('/').split('/')
            user = 'root' if parts[0] == 'root' else parts[1]
            f = self.safe_open(p)
            if not f:
                continue
            hosts, hashed = [], 0
            with f:
                for line in f:
                    t = line.split()
                    if not t or t[0].startswith('#'):
                        continue
                    if t[0].startswith('@'):
                        t = t[1:]
                    if not t:
                        continue
                    if t[0].startswith('|1|'):
                        hashed += 1
                        continue
                    for h in t[0].split(','):
                        m = re.match(r'^\[([^\]]+)\]:(\d+)$', h)
                        host, port = (m[1], m[2]) if m else (h, '22')
                        if [host.lower(), port] not in hosts:
                            hosts.append([host.lower(), port])
            self.known_hosts.append({'path': rp, 'user': user, 'hosts': hosts, 'hashed': hashed})
            self.sources.append({'path': rp, 'kind': 'known_hosts', 'events': 0})

    def ftp_ts(self, toks):
        try:
            return dt.datetime.strptime(' '.join(toks), '%a %b %d %H:%M:%S %Y').replace(tzinfo=self.tz).timestamp()
        except ValueError:
            return None

    # ───────────────────────── 상관분석 ─────────────────────────
    def merge_history_audit(self):
        """같은 명령이 셸 히스토리와 auditd 양쪽에 있으면 히스토리 쪽으로 합친다(파이프라인 원문 + 세션 정보)."""
        audits = defaultdict(list)
        for e in self.events:
            if e.get('via') == 'audit':
                audits[e['user']].append(e)
            elif e.get('via') == 'sudo' and e['ts'] is not None:
                e['argv0'] = e['cmd'].split()[0]
                audits[e['user']].append(e)
        for lst in audits.values():
            lst.sort(key=lambda e: e['ts'])
        drop = set()
        for h in self.events:
            if h.get('via') != 'history' or h.get('ts') is None or h['cat'] == 'db' and 'DB 히스토리' in h.get('tags', []):
                continue
            words = set(re.findall(r'[\w.\-]+', h['cmd']))
            for a in audits.get(h['user'], ()):
                if a['ts'] < h['ts'] - 2:
                    continue
                if a['ts'] > h['ts'] + 15:
                    break
                if id(a) in drop or os.path.basename(a['argv0']) not in words:
                    continue
                drop.add(id(a))
                if a.get('ses'):
                    h.setdefault('ses', a['ses'])
                label = 'auditd 확인' if a['via'] == 'audit' else 'sudo 로그 확인'
                if label not in h['tags']:
                    h['tags'].append(label)
                h['raw'] = h.get('raw', '') + f'\n── {a["via"]} ({a.get("src")}:{a.get("line")}) ──\n' + a.get('raw', '')
                if SEV_RANK[a['sev']] > SEV_RANK[h['sev']]:
                    h['sev'] = a['sev']
                for t in a['tags']:
                    if t.startswith('실행계정=') and t not in h['tags']:
                        h['tags'].append(t)
        self.events = [e for e in self.events if id(e) not in drop]

    def correlate(self):
        self.merge_history_audit()
        ev = self.events
        ev.sort(key=lambda e: (e['ts'] is None, e['ts'] or 0, e['seq']))

        sessions, by_pid, by_tty, ses_map = {}, {}, {}, {}
        fails = Counter()
        # btmp 는 auth 로그와 같은 실패를 중복 기록하므로, auth 로그에 실패가 없는 IP 에만 반영
        auth_fail_ips = {e.get('ip') for e in ev if e.get('kind') == 'login_fail'}
        for e in ev:
            if e.get('kind') == 'btmp' and e.get('ip') in auth_fail_ips:
                e['dup'] = True
                e['sev'] = 'low'
                e.setdefault('tags', []).append('auth 로그와 중복 집계 제외')

        def new_session(e, method, source):
            sid = f'S{len(sessions) + 1}'
            s = {'id': sid, 'user': e.get('user'), 'ip': e.get('ip'), 'host': e.get('host'), 'method': method,
                 'start': e['ts'], 'end': None, 'pid': e.get('pid'), 'tty': None, 'sources': [source],
                 'fails_before': fails[e.get('ip')] if e.get('ip') else 0}
            sessions[sid] = s
            return s

        def match_session(e, window=120):
            # audit 의 USER_LOGIN pid 는 sshd pid 와 같다. 그 외에는 같은 IP·근접 시각으로 맞춘다
            # (UID 0 별칭 계정은 audit 에서 root 로 보이므로 계정명은 우선순위로만 사용)
            if e.get('kind') == 'audit_login' and e.get('pid'):
                for (_, pid), s in by_pid.items():
                    if pid == e['pid'] and s['ip'] == e.get('ip'):
                        return s
            near = [s for s in sessions.values() if s['ip'] == e.get('ip') and abs(s['start'] - e['ts']) <= window]
            near.sort(key=lambda s: (s['user'] != e.get('user'), abs(s['start'] - e['ts'])))
            return near[0] if near else None

        backdoors = set(self.uid0_alias) | {e['target'] for e in ev if e.get('kind') == 'acct' and e.get('target')}

        # 1차: 로그인/세션 구간 구성
        for e in ev:
            k, ts = e.get('kind'), e['ts']
            if ts is None:
                continue
            if k == 'login_fail' or k == 'btmp' and not e.get('dup'):
                fails[e.get('ip')] += e.get('count', 1)
            elif k == 'login_ok':
                n = fails[e['ip']]
                if n >= 3 and e.get('method') == 'publickey':
                    e['sev'] = 'crit'
                    e['msg'] += ' — 무차별 대입을 하던 IP 가 SSH 키로 접속 (심어 둔 키 의심)'
                    e.setdefault('tags', []).append('침입 IP 키 로그인')
                elif n >= 3:
                    e['sev'] = 'crit'
                    e['msg'] += f' — 직전 실패 {n}회 후 성공 (무차별 대입 성공 의심)'
                    e.setdefault('tags', []).append('무차별 대입 성공')
                if e.get('user') in backdoors:
                    e['sev'] = 'crit'
                    uid0 = e['user'] in self.uid0_alias
                    e['msg'] += ' — ' + ('UID 0 백도어 계정' if uid0 else '침해 중 생성된 계정') + '으로 로그인'
                    e.setdefault('tags', []).append('백도어 계정')
                if e.get('detail'):
                    e.setdefault('tags', []).append('키: ' + e['detail'])
                s = new_session(e, e.get('method'), 'auth')
                e['sid'] = s['id']
                if e.get('pid'):
                    by_pid[(e.get('host'), e['pid'])] = s
            elif k in ('sess_open', 'sess_close', 'disconnect', 'sftp_req') and e.get('pid'):
                s = by_pid.get((e.get('host'), e['pid']))
                if s:
                    e['sid'] = s['id']
                    e.setdefault('ip', s['ip'])
                    if k in ('sess_close', 'disconnect') and s['end'] is None:
                        s['end'] = ts
                    if k == 'sftp_req':
                        s['method'] = (s['method'] or '') + ' · sftp'
            elif k in ('audit_login', 'wtmp_login'):
                s = match_session(e)
                if s is None:
                    s = new_session(e, None, 'audit' if k == 'audit_login' else 'wtmp')
                elif ('audit' if k == 'audit_login' else 'wtmp') not in s['sources']:
                    s['sources'].append('audit' if k == 'audit_login' else 'wtmp')
                e['sid'] = s['id']
                if k == 'audit_login' and e.get('ses'):
                    ses_map[e['ses']] = s
                if k == 'wtmp_login':
                    s['tty'] = e.get('tty')
                    by_tty[e.get('tty')] = s
            elif k == 'wtmp_logout':
                s = by_tty.pop(e.get('tty'), None)
                if s and s['end'] is None:
                    s['end'] = ts

        slist = sorted(sessions.values(), key=lambda s: s['start'])

        def active(ts, user=None, ip=None):
            found = []
            for s in slist:
                if s['start'] > ts + 1:
                    break
                if user and s['user'] != user or ip and s['ip'] != ip:
                    continue
                if ts <= (s['end'] if s['end'] is not None else float('inf')) + 1:
                    found.append(s)
            return found

        # 2차: 명령/전송/DB 이벤트를 세션에 연결
        for e in ev:
            if e['ts'] is None or e.get('sid'):
                continue
            s, inferred = None, False
            if e.get('ses') and e['ses'] in ses_map:
                s = ses_map[e['ses']]
            elif e.get('via') or e.get('kind') in ('sftp_xfer', 'sftp_op', 'su', 'sudo_fail'):
                cand = active(e['ts'], e.get('user'), e.get('ip'))
                s = cand[-1] if cand else None
            elif e.get('kind') in ('acct',) or (e['cat'] == 'db' and not e.get('ip')):
                cand = [x for x in active(e['ts']) if x['ip'] and not is_private(x['ip'])]
                if len(cand) == 1:
                    s, inferred = cand[0], True
            if s:
                e['sid'] = s['id']
                if e.get('via') == 'audit' and s['user'] and e.get('user') != s['user']:
                    e.setdefault('tags', []).append(f'audit 계정={e["user"]}')
                    e['user'] = s['user']
                if not e.get('ip') and s['ip']:
                    e['ip'] = s['ip']
                    if inferred:
                        e['ip_inferred'] = True
                        e.setdefault('tags', []).append('세션 시간대로 추정')

        # 로그 변조 의심: wtmp/audit 에는 있는데 auth 로그에는 없는 외부 로그인
        if self.has_auth:
            auth_ts = [e['ts'] for e in ev if e.get('src', '').startswith(('/var/log/auth', '/var/log/secure', 'journal'))
                       and e['ts'] is not None]
            auth_ips = {e['ip'] for e in ev if e.get('kind') == 'login_ok'}
            if auth_ts:
                lo, hi = min(auth_ts), max(auth_ts)
                missing = {}
                for e in ev:
                    if e.get('kind') in ('audit_login', 'wtmp_login') and e.get('ip') and e['ip'] not in auth_ips \
                            and lo <= e['ts'] <= hi + 3600 and not is_private(e['ip']):
                        missing.setdefault(e['ip'], e)
                for ip, e in missing.items():
                    self.add(e['ts'], 'antiforensic', 'crit',
                             f'auth 로그 삭제/변조 의심 — {ip} 로그인이 {e["src"]} 에는 있으나 auth 로그에는 없음',
                             kind='tamper', ip=ip, user=e.get('user'), sid=e.get('sid'), src=e['src'], line=e.get('line'))
                if missing:
                    ev = sorted(self.events, key=lambda e: (e['ts'] is None, e['ts'] or 0, e['seq']))

        # 세션 요약
        by_sid = defaultdict(list)
        for e in ev:
            if e.get('sid'):
                by_sid[e['sid']].append(e)
        for s in slist:
            es = by_sid.get(s['id'], [])
            s['cats'] = dict(Counter(e['cat'] for e in es if e['cat'] not in ('session',)))
            s['n'] = len(es)
            s['max_sev'] = max((e['sev'] for e in es), key=SEV_RANK.get, default='info')
            s['last'] = max((e['ts'] for e in es), default=s['start'])

        # 공격자 IP 프로필
        prof = {}
        for e in ev:
            ip = e.get('ip')
            if not ip or e.get('ip_inferred') and e['cat'] == 'auth':
                continue
            p = prof.get(ip)
            if p is None:
                p = prof[ip] = {'ip': ip, 'private': is_private(ip), 'fails': 0, 'ok': 0, 'tried': Counter(),
                                'ok_users': [], 'first': e['ts'], 'last': e['ts'], 'cats': Counter(),
                                'sev': Counter(), 'sessions': set()}
            k = e.get('kind')
            if k == 'login_fail':
                p['fails'] += 1
                if e.get('user'):
                    p['tried'][e['user']] += 1
            elif k == 'btmp' and not e.get('dup'):
                p['fails'] += e['count']
                for u, n in e.get('users', []):
                    p['tried'][u] += n
            elif k in ('invalid',) and e.get('user'):
                p['tried'][e['user']] += 0
            elif k == 'login_ok':
                p['ok'] += 1
                if e['user'] not in p['ok_users']:
                    p['ok_users'].append(e['user'])
            if e['ts'] is not None:
                p['first'] = e['ts'] if p['first'] is None else min(p['first'], e['ts'])
                p['last'] = e['ts'] if p['last'] is None else max(p['last'], e['ts'])
            if e['cat'] not in ('auth', 'session'):
                p['cats'][e['cat']] += 1
            p['sev'][e['sev']] += 1
            if e.get('sid'):
                p['sessions'].add(e['sid'])
        ips = []
        for p in prof.values():
            score = p['ok'] * 30 + (10 if p['fails'] >= 5 else 0) + min(p['fails'], 200) * 0.2 \
                + p['sev']['crit'] * 15 + p['sev']['high'] * 6 + p['sev']['med'] * 2
            if p['private']:
                score *= 0.5
            p.update(score=round(score, 1), tried=p['tried'].most_common(15), cats=dict(p['cats']),
                     sev=dict(p['sev']), sessions=sorted(p['sessions'], key=lambda x: int(x[1:])))
            ips.append(p)
        ips.sort(key=lambda p: -p['score'])

        # 접속 방향: ⬇ 들어온 접속(다른 곳 → 이 서버) / ⬆ 나간 접속(이 서버 → 다른 곳)
        self_ips = set(self.server_ips) | self.server_ips_auto
        outs = []
        for e in ev:
            if e.get('cmd') and e.get('via') and 'DB 히스토리' not in (e.get('tags') or []):
                t = outbound_targets(e['cmd'])
                if t:
                    e['dest'], e['dir'] = t, 'out'
                    if e['ts'] is not None:
                        outs.append(e)
            elif e.get('ip') and not e.get('ip_inferred') and not e.get('via'):
                e['dir'] = 'in'
        # 서버가 자기 자신에게 SSH 로 다시 들어온 경우: 직전에 ssh 를 실행한 세션과 연결
        for e in ev:
            if e.get('kind') != 'login_ok' or e['ts'] is None:
                continue
            ip = e.get('ip') or ''
            cands = [o for o in outs if e['ts'] - 120 <= o['ts'] <= e['ts'] + 2 and o.get('sid') != e.get('sid')
                     and any(d['proto'] in ('ssh', 'sftp', 'scp', 'rsync') and
                             (d['host'] == ip or host_kind(d['host'], self_ips) == 'self') for d in o['dest'])]
            if host_kind(ip, self_ips) == 'self' or any(d['host'] == ip for o in cands for d in o['dest']):
                self_ips.add(ip) if ip not in LOOPBACK and not ip.startswith('127.') else None
                e['self_origin'] = True
                e.setdefault('tags', []).append('서버 내부에서 출발')
                s = sessions.get(e.get('sid'))
                if s:
                    s['self_origin'] = True
                if cands:
                    o = cands[-1]
                    e['origin'] = o
                    if s:
                        s['origin_sid'] = o.get('sid')
        for e in ev:
            for d in e.get('dest', []):
                d['kind'] = host_kind(d['host'], self_ips)

        out_events, index = [], {}
        for e in ev:
            if not e.get('hidden'):
                index[id(e)] = len(out_events)
                out_events.append(e)
        for n, e in enumerate(out_events):
            o = e.get('origin')
            e = {k: v for k, v in e.items() if k not in ('seq', 'argv0', 'hidden', 'dup', 'users')}
            if o:
                e['origin'] = {'i': index.get(id(o)), 'sid': o.get('sid'), 'ip': o.get('ip'), 'cmd': o.get('cmd')}
            annotate(e)
            out_events[n] = e

        # 파일 작업
        for e in out_events:
            ops = []
            if e.get('cmd') and e.get('via') and 'DB 히스토리' not in (e.get('tags') or []):
                ops = file_ops(e['cmd'], e.get('cwd'))
            elif e.get('kind') == 'sftp_xfer' and e.get('path'):
                ops = [{'op': '외부로 유출' if '다운로드' in e['msg'] else '외부에서 반입', 'path': e['path'],
                        'how': f'SFTP {"다운로드" if "다운로드" in e["msg"] else "업로드"} {human_bytes(e.get("bytes", 0))}'}]
            elif e.get('kind') == 'sftp_op' and e.get('cmd'):
                op = {'remove': '삭제', 'rename': '이동', 'mkdir': '생성', 'rmdir': '삭제'}.get(e['msg'].split()[-1])
                src, _, to = e['cmd'].partition(' → ')
                if op:
                    ops = [{'op': op, 'path': src, 'how': 'SFTP ' + e['msg'].split()[-1], **({'to': to} if to else {})}]
            elif e.get('kind') == 'ftp_xfer' and e.get('cmd'):
                ops = [{'op': '외부로 유출' if '다운로드' in e['msg'] else '외부에서 반입', 'path': e['cmd'], 'how': 'FTP'}]
            if ops:
                if e['cat'] == 'db':
                    for f in ops:
                        if f['op'] == '저장':
                            f['how'] = 'DB 덤프 결과 저장'
                e['files'] = ops
        fagg = {}
        for n, e in enumerate(out_events):
            for f in e.get('files', []):
                for path, op in ((f['path'], f['op']), (f.get('to'), '이동해 온 곳' if f['op'] == '이동' else '복사본')):
                    if not path:
                        continue
                    a = fagg.setdefault(path, {'path': path, 'ops': [], 'sev': 'info', 'flags': []})
                    a['ops'].append({'i': n, 'ts': e['ts'], 'op': op, 'how': f['how'], 'user': e.get('user'),
                                     'sid': e.get('sid'), **({'to': f['to']} if f.get('to') and path == f['path'] else {}),
                                     **({'from': f['path']} if path == f.get('to') else {})})
                    if SEV_RANK[e['sev']] > SEV_RANK[a['sev']]:
                        a['sev'] = e['sev']
        for a in fagg.values():
            a['ops'].sort(key=lambda o: (o['ts'] is None, o['ts'] or 0, o['i']))
            kinds = {o['op'] for o in a['ops']}
            if '외부로 유출' in kinds:
                a['flags'].append('유출')
            if '삭제' in kinds:
                a['flags'].append('삭제됨' if a['ops'][-1]['op'] == '삭제' else '삭제 기록')
            if HIDDEN_RX.search(a['path']):
                a['flags'].append('숨김 경로')
        file_list = sorted(fagg.values(), key=lambda a: (-('유출' in a['flags']), -SEV_RANK[a['sev']], -len(a['ops']), a['path']))

        # 나간 접속 목적지 요약
        agg = {}
        for n, e in enumerate(out_events):
            for d in e.get('dest', []):
                a = agg.setdefault(d['host'], {'host': d['host'], 'kind': d['kind'], 'ports': [], 'whats': Counter(),
                                               'count': 0, 'first': None, 'last': None, 'users': [], 'sessions': [],
                                               'src_ips': [], 'events': [], 'sev': 'info', 'known_by': []})
                a['count'] += 1
                a['whats'][d['what']] += 1
                for key, val in (('ports', d.get('port')), ('users', e.get('user')), ('sessions', e.get('sid')), ('src_ips', e.get('ip'))):
                    if val and val not in a[key]:
                        a[key].append(val)
                if e['ts'] is not None:
                    a['first'] = e['ts'] if a['first'] is None else min(a['first'], e['ts'])
                    a['last'] = e['ts'] if a['last'] is None else max(a['last'], e['ts'])
                a['events'].append(n)
                if SEV_RANK[e['sev']] > SEV_RANK[a['sev']]:
                    a['sev'] = e['sev']
        for kh in self.known_hosts:
            for host, port in kh['hosts']:
                a = agg.setdefault(host, {'host': host, 'kind': host_kind(host, self_ips), 'ports': [port], 'whats': Counter(),
                                          'count': 0, 'first': None, 'last': None, 'users': [], 'sessions': [],
                                          'src_ips': [], 'events': [], 'sev': 'info', 'known_by': []})
                if kh['user'] not in a['known_by']:
                    a['known_by'].append(kh['user'])
        outbound = sorted(agg.values(), key=lambda a: (-SEV_RANK[a['sev']], -a['count'], a['host']))
        for a in outbound:
            a['whats'] = a['whats'].most_common()
        for p in ips:
            p['self'] = host_kind(p['ip'], self_ips) == 'self'
        tss = [e['ts'] for e in out_events if e['ts'] is not None]
        off = self.tz.utcoffset(dt.datetime.now()).total_seconds() / 60
        return {
            'meta': {
                'generated': dt.datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S'),
                'root': self.root, 'hosts': [h for h, _ in self.hosts.most_common(5)],
                'tz_offset_min': off, 'tz_label': 'UTC' + ('+' if off >= 0 else '-') + f'{int(abs(off)) // 60:02d}:{int(abs(off)) % 60:02d}',
                'range': [min(tss), max(tss)] if tss else None,
                'sources': self.sources, 'notes': self.notes, 'version': '1.1',
                'server_ips': sorted(self.server_ips | self.server_ips_auto), 'server_ips_auto': sorted(self.server_ips_auto),
            },
            'cats': CATS,
            'events': out_events,
            'sessions': slist,
            'ips': ips,
            'histories': self.histories,
            'outbound': outbound,
            'files': file_list,
            'known_hosts': self.known_hosts,
        }


# ───────────────────────── 출력 ─────────────────────────
def render_html(data):
    payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
    return HTML_TEMPLATE.replace('__SECVIEW_DATA__', payload)


def empty_data(tz):
    d = Analyzer(tempfile.gettempdir(), tz).correlate()
    d['meta'].update(root='', empty=True)
    return d


# ───────────────────────── 웹 업로드 ─────────────────────────
# 브라우저에서 올린 파일(개별 파일, 폴더, zip/tar.gz)을 임시 디렉터리에 / 구조로 배치한 뒤 Analyzer 로 분석한다.
SCAN_GLOBS = ['root/.ssh/known_hosts*', 'home/*/.ssh/known_hosts*', 'var/log/auth.log*', 'var/log/secure*', 'var/log/audit/audit.log*', 'var/log/wtmp*', 'var/log/btmp*',
              'root/.*_history', 'root/.history', 'home/*/.*_history', 'home/*/.history', 'var/lib/*/.*_history',
              'srv/*/.*_history', 'var/log/mysql/*.log*', 'var/log/mysql*.log*', 'var/log/mariadb/*.log*',
              'var/lib/mysql/*.log', 'var/log/postgresql/*.log*', 'var/lib/pgsql/*.log', 'var/lib/postgresql/*.log',
              'var/log/xferlog*', 'var/log/vsftpd.log*', 'var/log/proftpd/xferlog*', 'etc/passwd']
SKIP_RX = re.compile(r'(?:^|/)(?:journal|\.git|__MACOSX)/|\.(?:png|jpe?g|gif|exe|dll|so|pyc|py|html?|js|css|pdf|docx?|xlsx?|pptx?)$', re.I)
AUTH_PROGS = {'sshd', 'sudo', 'su', 'useradd', 'usermod', 'userdel', 'passwd', 'chpasswd', 'groupadd',
              'internal-sftp', 'sftp-server'}
ARCHIVE_RX = re.compile(r'\.(?:tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz)$', re.I)
MAX_UPLOAD = 8 * 1024 ** 3


def _is_gz(path):
    with open(path, 'rb') as f:
        return f.read(2) == b'\x1f\x8b'


def sniff(path, name):
    """파일 내용으로 로그 종류를 추정한다 → (종류, gzip 여부)"""
    gz = _is_gz(path)
    try:
        with (gzip.open(path, 'rb') if gz else open(path, 'rb')) as f:
            data = f.read(65536)
    except (OSError, EOFError):
        return None, gz
    size = os.path.getsize(path)
    if not gz and size and size % 384 == 0 and len(data) >= 384 and b'\0\0\0' in data[:384]:
        if 0 <= struct.unpack_from('<h', data)[0] <= 9:
            return ('btmp' if 'btmp' in name.lower() else 'wtmp'), gz
    lines = data.decode('utf-8', 'replace').splitlines()[:500]
    if any(AUDIT_HDR.search(l) for l in lines):
        return 'audit', gz
    for l in lines:
        m = SYSLOG_RE.match(l)
        if m and m['prog'] in AUTH_PROGS:
            return 'auth', gz
    if any(Analyzer.MYSQL_RX.match(l) for l in lines):
        return 'mysql', gz
    if any(Analyzer.PG_RX.match(l) for l in lines):
        return 'pg', gz
    if any(re.search(r'(?:OK|FAIL) (?:DOWNLOAD|UPLOAD|LOGIN):|^\w{3} \w{3}\s+\d+ [\d:]+ \d{4} \d+ \S+ \d+ ', l) for l in lines):
        return 'ftp', gz
    return None, gz


def place_target(name, path, n):
    """업로드 파일을 분석 루트의 어느 경로에 둘지 정한다 (못 쓰는 파일이면 None)."""
    parts = [re.sub(r'[<>:"|?*\x00-\x1f]', '_', p) for p in re.split(r'[\\/]+', name) if p not in ('', '.', '..')]
    if not parts:
        return None
    joined = '/'.join(parts)
    if SKIP_RX.search(joined):
        return None
    # 1) 원래 경로 구조 유지 (evidence/var/log/auth.log → var/log/auth.log)
    s = '/' + joined
    idx = [i for i in (s.find('/' + m) for m in ('var/log/', 'root/', 'home/', 'etc/passwd', 'var/lib/', 'srv/')) if i >= 0]
    if idx:
        cand = s[min(idx) + 1:]
        if any(fnmatch.fnmatchcase(cand, g) for g in SCAN_GLOBS):
            return cand
    # 2) 파일명
    b, bl = parts[-1], parts[-1].lower()
    gzs = '.gz' if _is_gz(path) and not bl.endswith('.gz') else ''
    m = re.match(r'^\.?(bash|zsh|sh|ash|mysql|psql)_history', bl)
    if m:
        user = parts[-2] if len(parts) >= 2 else None
        if user and (user.lower() in ('root', 'home', 'tmp', 'log', 'logs', 'evidence', 'history')
                     or not re.fullmatch(r'[a-z_][a-z0-9_.-]{0,31}', user)):
            user = None
        return f'home/{user}/.{m[1]}_history' if user else f'root/.{m[1]}_history'
    for rx, d in ((r'^(?:auth\.log|secure)', 'var/log/'), (r'^audit\.log', 'var/log/audit/'), (r'^[wb]tmp', 'var/log/'),
                  (r'^(?:xferlog|vsftpd\.log)', 'var/log/'), (r'^passwd$', 'etc/'), (r'^known_hosts', 'root/.ssh/')):
        if re.match(rx, bl):
            return d + b + gzs
    # 3) 내용 (messages, syslog, 이름이 바뀐 파일 등)
    kind, gz = sniff(path, name)
    gzs = '.gz' if gz else ''
    return {'auth': f'var/log/auth.log.{n}{gzs}', 'audit': f'var/log/audit/audit.log.{n}{gzs}',
            'mysql': f'var/log/mysql/upload{n}.log{gzs}', 'pg': f'var/log/postgresql/upload{n}.log{gzs}',
            'ftp': f'var/log/xferlog.{n}{gzs}', 'wtmp': f'var/log/wtmp.{n}', 'btmp': f'var/log/btmp.{n}'}.get(kind)


class UploadJob:
    def __init__(self, base, job_id):
        self.dir = os.path.join(base, job_id)
        self.root = os.path.join(self.dir, 'root')
        os.makedirs(self.root, exist_ok=True)
        self.n = 0
        self.names = {}  # '/var/log/auth.log' → 업로드한 원래 이름
        self.hashes = {}  # 내용 sha1 → 원래 이름 (같은 파일을 두 번 올려도 한 번만 분석)
        self.lock = threading.Lock()

    def tmpfile(self):
        self.n += 1
        return os.path.join(self.dir, f'in{self.n}')

    def place(self, tmp, name, mtime, res):
        self.n += 1
        target = None
        h = hashlib.sha1()
        with open(tmp, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        digest = h.hexdigest()
        if digest in self.hashes:
            os.remove(tmp)
            res.setdefault('dups', []).append([name, self.hashes[digest]])
            return
        if os.path.getsize(tmp) > 0:
            target = place_target(name, tmp, self.n)
        if not target:
            os.remove(tmp)
            res['skipped'].append(name)
            return
        if os.path.exists(os.path.join(self.root, target)):
            if target.endswith('_history'):
                target = f'home/upload{self.n}/' + target.rsplit('/', 1)[1]
            else:
                base, gz = (target[:-3], '.gz') if target.endswith('.gz') else (target, '')
                target = f'{base}.u{self.n}{gz}'
        dst = os.path.join(self.root, *target.split('/'))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(tmp, dst)
        if mtime:
            try:
                os.utime(dst, (mtime, mtime))
            except (OSError, OverflowError, ValueError):
                pass
        self.names['/' + target] = name
        self.hashes[digest] = name
        res['placed'].append([name, '/' + target])

    def ingest(self, src, name, mtime):
        res = {'name': name, 'placed': [], 'skipped': []}
        with self.lock:
            try:
                if name.lower().endswith('.zip') and zipfile.is_zipfile(src):
                    with zipfile.ZipFile(src) as z:
                        for info in z.infolist():
                            if info.is_dir():
                                continue
                            tmp = self.tmpfile()
                            with z.open(info) as fi, open(tmp, 'wb') as fo:
                                shutil.copyfileobj(fi, fo)
                            self.place(tmp, info.filename, time.mktime(info.date_time + (0, 0, -1)), res)
                    os.remove(src)
                elif ARCHIVE_RX.search(name) and tarfile.is_tarfile(src):
                    with tarfile.open(src, 'r:*') as t:
                        for m in t:
                            if not m.isfile():
                                continue
                            tmp = self.tmpfile()
                            with t.extractfile(m) as fi, open(tmp, 'wb') as fo:
                                shutil.copyfileobj(fi, fo)
                            self.place(tmp, m.name, m.mtime, res)
                    os.remove(src)
                else:
                    self.place(src, name, mtime, res)
            except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError) as ex:
                res['error'] = f'{type(ex).__name__}: {ex}'
        res['skipped_count'] = len(res['skipped'])
        res['skipped'] = res['skipped'][:100]
        return res

    def analyze(self, tz, server_ips=()):
        data = Analyzer(self.root, tz, server_ips=server_ips).run()
        rename = lambda p: self.names.get(p, p)
        for e in data['events']:
            if e.get('src') in self.names:
                e['src'] = rename(e['src'])
        for s in data['meta']['sources']:
            s['path'] = rename(s['path'])
        for h in data['histories'] + data['known_hosts']:
            h['path'] = rename(h['path'])
        data['meta']['root'] = f'웹 업로드 ({len(self.names)}개 파일)'
        return data


def serve(data, bind, port, open_browser=False):
    base = tempfile.mkdtemp(prefix='secviewer_')
    jobs = {}
    state = {'data': data}

    class H(http.server.BaseHTTPRequestHandler):
        server_version = 'secviewer'

        def send(self, code, body, ctype='application/json; charset=utf-8'):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False)
            body = body.encode('utf-8') if isinstance(body, str) else body
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path in ('/', '/index.html'):
                self.send(200, render_html(state['data']), 'text/html; charset=utf-8')
            elif path == '/api/ping':
                self.send(200, {'ok': True, 'upload': True, 'job': state.get('job')})
            else:
                self.send(404, {'error': 'not found'})

        def do_POST(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            job_id = q.get('job', [''])[0]
            if not re.fullmatch(r'[0-9a-f]{16,40}', job_id):
                return self.send(400, {'error': 'job id 오류'})
            job = jobs.get(job_id) or jobs.setdefault(job_id, UploadJob(base, job_id))
            if u.path == '/api/upload':
                length = int(self.headers.get('Content-Length') or 0)
                if length > MAX_UPLOAD:
                    return self.send(413, {'error': '파일이 너무 큽니다'})
                name = q.get('name', ['upload'])[0]
                try:
                    mtime = float(q.get('mtime', ['0'])[0]) / 1000
                except ValueError:
                    mtime = 0
                tmp = job.tmpfile()
                with open(tmp, 'wb') as f:
                    left = length
                    while left > 0:
                        chunk = self.rfile.read(min(1 << 20, left))
                        if not chunk:
                            break
                        f.write(chunk)
                        left -= len(chunk)
                self.send(200, job.ingest(tmp, name, mtime))
            elif u.path == '/api/analyze':
                try:
                    tz = tz_from_str(q.get('tz', ['local'])[0])
                except argparse.ArgumentTypeError:
                    tz = tz_from_str('local')
                t0 = time.time()
                data = job.analyze(tz, re.split(r'[,\s]+', q.get('server_ip', [''])[0]))
                # 직전 결과에 이어서 올릴 수 있도록 이번 작업 폴더는 남기고, 그 전 작업은 정리
                old = state.get('job')
                if old and old != job_id and old in jobs:
                    shutil.rmtree(jobs.pop(old).dir, ignore_errors=True)
                state['job'] = job_id
                data['meta']['job'] = job_id
                state['data'] = data
                print(f'[+] 웹 업로드 분석: 파일 {len(job.names)}개 → 이벤트 {len(data["events"])}건 ({time.time() - t0:.1f}s)')
                self.send(200, data)
            else:
                self.send(404, {'error': 'not found'})

        def log_message(self, *a):
            pass

    http.server.ThreadingHTTPServer.allow_reuse_address = True
    srv = http.server.ThreadingHTTPServer((bind, port), H)
    url = f'http://{"127.0.0.1" if bind in ("0.0.0.0", "") else bind}:{port}/'
    print(f'[*] 뷰어: {url}   (Ctrl+C 로 종료)')
    print('    화면에 로그 파일·폴더·압축파일(zip, tar.gz)을 끌어다 놓으면 분석합니다.')
    if bind in ('127.0.0.1', 'localhost'):
        print(f'    원격 서버라면 내 PC 에서:  ssh -L {port}:127.0.0.1:{port} <서버>  후 브라우저로 접속')
    else:
        print('[!] 외부에서 접속 가능한 주소로 열었습니다. 누구나 로그를 올리고 결과를 볼 수 있습니다.')
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        shutil.rmtree(base, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description='리눅스 침해사고 보안 로그 뷰어 (SSH 침입 / 명령 / DB 덤프 / 파일 전송)')
    ap.add_argument('--root', default='/', help='분석할 루트 디렉터리 (기본 /). 수집한 증거 폴더를 / 구조 그대로 지정')
    ap.add_argument('-o', '--output', default='secview_report.html', help='HTML 리포트 경로')
    ap.add_argument('--json', help='분석 결과 JSON 도 저장')
    ap.add_argument('--tz', type=tz_from_str, default=tz_from_str('local'),
                    help='syslog 시각의 시간대 (예: +09:00, UTC). 기본은 이 PC 시간대')
    ap.add_argument('--year', type=int, help='연도가 없는 syslog 의 연도 (기본: 파일 수정시각으로 추정)')
    ap.add_argument('--since', help='이 시각 이후만 (예: 2026-10-01 또는 2026-10-01T02:00)')
    ap.add_argument('--server-ip', default='', help='분석 대상 서버 자신의 IP (쉼표로 여러 개). 자기 자신에서 출발한 접속을 구분')
    ap.add_argument('--audit-all', action='store_true', help='auditd 에서 로그인 세션이 없는(데몬) 명령도 포함')
    ap.add_argument('--no-journal', action='store_true', help='auth 로그가 없어도 journalctl 을 쓰지 않음')
    ap.add_argument('--serve', nargs='?', const=8080, type=int, metavar='PORT',
                    help='분석 후 리포트를 HTTP 로 띄움 (기본 8080, 웹 업로드도 가능)')
    ap.add_argument('--web', nargs='?', const=8080, type=int, metavar='PORT',
                    help='분석 없이 업로드 화면으로 시작 — 브라우저에 로그 파일을 끌어다 놓아 분석 (기본 8080)')
    ap.add_argument('--bind', default='127.0.0.1', help='--serve/--web 바인드 주소 (기본 127.0.0.1)')
    ap.add_argument('--no-browser', action='store_true', help='--web 에서 브라우저 자동 실행 안 함')
    a = ap.parse_args()

    if os.name == 'nt' and a.root == '/' and not a.serve and not a.web:
        print('[*] Windows 에서는 분석할 / 가 없으므로 업로드 화면(--web)으로 시작합니다.')
        a.web = 8080
    if a.web:
        serve(empty_data(a.tz), a.bind, a.web, open_browser=not a.no_browser)
        return

    since = None
    if a.since:
        since = Analyzer('/', a.tz).ts_iso(a.since if 'T' in a.since or ' ' in a.since else a.since + 'T00:00:00')
        if since is None:
            ap.error('--since 형식: YYYY-MM-DD 또는 YYYY-MM-DDTHH:MM:SS')
    if not os.path.isdir(a.root):
        ap.error(f'디렉터리가 없습니다: {a.root}')
    if a.root == '/' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print('[!] root 가 아니면 auth.log / audit.log / btmp 를 못 읽을 수 있습니다. sudo 로 실행을 권장합니다.')

    t0 = time.time()
    an = Analyzer(a.root, a.tz, a.year, a.audit_all, not a.no_journal, since, re.split(r'[,\s]+', a.server_ip))
    data = an.run()
    with open(a.output, 'w', encoding='utf-8') as f:
        f.write(render_html(data))
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=1)

    ev = data['events']
    cnt = Counter(e['cat'] for e in ev)
    crit = sum(1 for e in ev if e['sev'] == 'crit')
    print(f'[+] 로그 소스 {len(data["meta"]["sources"])}개, 이벤트 {len(ev)}건 ({time.time() - t0:.1f}s)')
    print(f'    치명 {crit} · SSH 인증 {cnt["auth"]} · DB {cnt["db"]} · 파일전송 {cnt["transfer"]} · '
          f'세션 {len(data["sessions"])} · IP {len(data["ips"])}')
    for n in data['meta']['notes']:
        print(f'[!] {n}')
    print(f'[+] 리포트: {os.path.abspath(a.output)}')
    if a.serve:
        serve(data, a.bind, a.serve)


# ───────────────────────── HTML 뷰어 ─────────────────────────
HTML_TEMPLATE = r'''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>침해사고 로그 뷰어</title>
<style>
:root{
  --bg:#0b0f15;--panel:#121821;--panel2:#18202b;--line:#253041;--line2:#1d2633;
  --text:#e4eaf2;--muted:#8a97a8;--faint:#5c697b;--c-rest:#4a586b;--accent:#5b9dff;--accent-bg:#1a2b47;
  --crit:#ff4d5e;--high:#ff9a3d;--med:#e9c04a;--low:#58a6ff;--info:#6b7787;
  --crit-bg:rgba(255,77,94,.10);--high-bg:rgba(255,154,61,.07);
  --c-auth:#5b9dff;--c-session:#8f86f0;--c-cmd:#94a3b8;--c-db:#ff5f9e;--c-transfer:#ff9a3d;
  --c-persist:#c78bff;--c-antiforensic:#ff4d5e;--c-exec:#f97316;--c-privesc:#e9c04a;--c-recon:#34c47c;--c-lateral:#22d3ee;--c-fileop:#d6a35c;
  --mono:ui-monospace,"Cascadia Mono","D2Coding",Consolas,"SFMono-Regular",monospace;
  --sans:"Pretendard","Apple SD Gothic Neo","Malgun Gothic",system-ui,-apple-system,"Segoe UI",sans-serif;
  color-scheme:dark;
}
:root[data-theme=light]{
  --bg:#f5f7fa;--panel:#ffffff;--panel2:#f0f3f7;--line:#d9dfe7;--line2:#e7ebf0;
  --text:#18212d;--muted:#5d6b7c;--faint:#8b97a6;--c-rest:#b4bfcc;--accent:#2563eb;--accent-bg:#e5eeff;
  --crit:#d92638;--high:#d9690f;--med:#a77d00;--low:#2563eb;--info:#7a8594;
  --crit-bg:rgba(217,38,56,.07);--high-bg:rgba(217,105,15,.05);
  --c-auth:#2563eb;--c-session:#6d5ae6;--c-cmd:#64748b;--c-db:#d6337a;--c-transfer:#d9690f;
  --c-persist:#9a4ee0;--c-antiforensic:#d92638;--c-exec:#c2410c;--c-privesc:#a77d00;--c-recon:#15803d;--c-lateral:#0e7490;--c-fileop:#92400e;
  color-scheme:light;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--accent);cursor:pointer;text-decoration:none}
a:hover{text-decoration:underline}
code,.mono{font-family:var(--mono);font-size:12.5px}
button{font:inherit;color:inherit}
header{position:sticky;top:0;z-index:20;background:var(--bg);border-bottom:1px solid var(--line)}
.hwrap{max-width:1560px;margin:0 auto;padding:12px 20px 0;display:flex;flex-wrap:wrap;align-items:center;gap:6px 18px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.01em}
.brand svg{color:var(--crit)}
.meta{color:var(--muted);font-size:12.5px;display:flex;gap:14px;flex-wrap:wrap}
.meta b{color:var(--text);font-weight:600}
.spacer{flex:1}
.iconbtn{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 10px;cursor:pointer;font-size:12.5px;color:var(--muted)}
.iconbtn:hover{color:var(--text);border-color:var(--faint)}
nav{max-width:1560px;margin:0 auto;padding:0 20px;display:flex;gap:2px;overflow-x:auto}
nav button{background:none;border:0;border-bottom:2px solid transparent;padding:10px 14px;cursor:pointer;color:var(--muted);font-weight:600;white-space:nowrap}
nav button:hover{color:var(--text)}
nav button.on{color:var(--text);border-bottom-color:var(--accent)}
nav .n{font-weight:500;color:var(--faint);font-size:12px;margin-left:4px}
main{max-width:1560px;margin:0 auto;padding:18px 20px 60px}
h2{font-size:15px;margin:0 0 10px;font-weight:700;letter-spacing:-.01em}
h2 small{font-weight:500;color:var(--muted);font-size:12.5px;margin-left:6px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.grid2{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:16px;align-items:start}
@media (max-width:1000px){.grid2{grid-template-columns:1fr}}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:16px}

@media (max-width:560px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;cursor:pointer;text-align:left;position:relative;overflow:hidden}
.kpi:hover{border-color:var(--faint)}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--k)}
.kpi .l{color:var(--muted);font-size:12.5px}
.kpi .v{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.02em;line-height:1.25}
.kpi .s{color:var(--faint);font-size:11.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi.zero .v{color:var(--faint)}
.notes{border:1px solid color-mix(in srgb,var(--high) 45%,transparent);background:var(--high-bg);border-radius:10px;padding:10px 14px;margin-bottom:16px;font-size:13px}
.notes div::before{content:"⚠ ";color:var(--high)}
/* 흐름 */
.flow{list-style:none;margin:0;padding:0;position:relative}
.flow li{display:grid;grid-template-columns:72px 14px minmax(0,1fr);gap:10px;padding:6px 0;cursor:pointer;border-radius:8px}
.flow li:hover{background:var(--panel2)}
.flow .t{font-family:var(--mono);font-size:12px;color:var(--muted);text-align:right;padding-top:2px}
.flow .t span{display:block;font-size:10.5px;color:var(--faint)}
.flow .dot{width:10px;height:10px;border-radius:50%;margin-top:6px;background:var(--c);box-shadow:0 0 0 3px color-mix(in srgb,var(--c) 22%,transparent)}
.flow .b{min-width:0}
.flow .m{font-weight:600}
.flow code{display:block;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:1px}
.flow .who{color:var(--faint);font-size:12px}
.daysep{font-size:11.5px;color:var(--faint);padding:8px 0 2px 96px;font-weight:600}
/* 배지 */
.sev{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;white-space:nowrap;color:var(--s)}
.sev::before{content:"";width:8px;height:8px;border-radius:2px;background:var(--s)}
.sev.crit{--s:var(--crit)}.sev.high{--s:var(--high)}.sev.med{--s:var(--med)}.sev.low{--s:var(--low)}.sev.info{--s:var(--info)}
.cat{display:inline-block;font-size:11.5px;font-weight:600;padding:1px 7px;border-radius:5px;white-space:nowrap;
  color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);border:1px solid color-mix(in srgb,var(--c) 30%,transparent)}
.tag{display:inline-block;font-size:11px;padding:0 6px;border-radius:4px;background:var(--panel2);color:var(--muted);border:1px solid var(--line);margin:1px 3px 1px 0;white-space:nowrap}
.tag.hot{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 40%,transparent);background:var(--crit-bg)}
/* 툴바 */
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.search{flex:1 1 260px;min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 10px;color:var(--text);font:inherit}
.search:focus,select:focus{outline:2px solid color-mix(in srgb,var(--accent) 50%,transparent);border-color:var(--accent)}
select{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:6px 8px;color:var(--text);font:inherit}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.chip{border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:3px 10px;cursor:pointer;font-size:12.5px;display:inline-flex;align-items:center;gap:6px;color:var(--muted)}
.chip i{width:8px;height:8px;border-radius:50%;background:var(--c);opacity:.35}
.chip.on{color:var(--text);border-color:color-mix(in srgb,var(--c) 55%,transparent);background:color-mix(in srgb,var(--c) 10%,var(--panel))}
.chip.on i{opacity:1}
.chip .n{color:var(--faint);font-size:11.5px;font-variant-numeric:tabular-nums}
.pill{display:inline-flex;align-items:center;gap:6px;background:var(--accent-bg);color:var(--text);border-radius:999px;padding:3px 6px 3px 10px;font-size:12.5px}
.pill button{border:0;background:none;cursor:pointer;color:var(--muted);font-size:14px;line-height:1;padding:0 3px}
.count{color:var(--muted);font-size:12.5px;margin-left:auto}
/* 표 */
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
table{border-collapse:collapse;width:100%;min-width:980px}
th{position:sticky;top:0;background:var(--panel2);text-align:left;font-size:12px;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid var(--line2);vertical-align:top}
tr.ev{cursor:pointer}
tr.ev:hover td{background:var(--panel2)}
tr.ev.crit td{background:var(--crit-bg)}
tr.ev.crit td:first-child{box-shadow:inset 3px 0 0 var(--crit)}
tr.ev.high td:first-child{box-shadow:inset 3px 0 0 var(--high)}
tr.ev.open td{background:var(--panel2)}
td.t{font-family:var(--mono);font-size:12px;white-space:nowrap;color:var(--muted)}
td.m{min-width:380px}
td.m .msg{font-weight:600}
td.m code{display:block;margin-top:2px;white-space:pre-wrap;word-break:break-all;color:var(--text);opacity:.9}
td.src{font-family:var(--mono);font-size:11.5px;color:var(--faint);width:150px;max-width:150px;word-break:break-all}
td.ipc{white-space:nowrap;font-family:var(--mono);font-size:12.5px}
.inferred{font-style:italic;opacity:.75}
tr.detail td{background:var(--bg);padding:12px 16px}
.kv{display:grid;grid-template-columns:110px minmax(0,1fr);gap:4px 12px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;min-width:0}
pre.raw{margin:0;padding:10px 12px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;font:12px/1.55 var(--mono);white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}
.more{display:block;margin:12px auto 0;padding:8px 18px}
.empty{padding:40px;text-align:center;color:var(--muted)}
/* 공격자 */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card.hot{border-color:color-mix(in srgb,var(--crit) 55%,transparent)}
.card h3{margin:0;font:600 16px var(--mono);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{font:600 11px var(--sans);padding:1px 7px;border-radius:5px;background:var(--panel2);color:var(--muted);border:1px solid var(--line)}
.badge.red{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 45%,transparent);background:var(--crit-bg)}
.score{height:4px;border-radius:2px;background:var(--line2);margin:10px 0 12px;overflow:hidden}
.score i{display:block;height:100%;background:linear-gradient(90deg,var(--high),var(--crit))}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}
.stats div{background:var(--panel2);border-radius:8px;padding:6px 10px}
.stats b{display:block;font-size:18px;font-variant-numeric:tabular-nums}
.stats span{font-size:11.5px;color:var(--muted)}
.row{font-size:12.5px;color:var(--muted);margin:4px 0}
.row b{color:var(--text);font-weight:500}
.acts{display:flex;gap:8px;margin-top:12px}
/* 세션 */
.sess{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;overflow:hidden}
.sess.hot{border-color:color-mix(in srgb,var(--crit) 50%,transparent)}
.sess>summary{list-style:none;cursor:pointer;padding:12px 16px;display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center}
.sess>summary::-webkit-details-marker{display:none}
.sess>summary::before{content:"▸";color:var(--faint);transition:transform .15s}
.sess[open]>summary::before{transform:rotate(90deg)}
.sess .who{font:600 14px var(--mono)}
.sess .when{color:var(--muted);font-size:12.5px;font-family:var(--mono)}
.sess .body{border-top:1px solid var(--line);padding:6px 0}
.sline{display:grid;grid-template-columns:76px 96px minmax(0,1fr);gap:10px;padding:5px 16px;font-size:13px;cursor:pointer}
.sline:hover{background:var(--panel2)}
.sline .t{font:12px var(--mono);color:var(--muted)}
.sline code{white-space:pre-wrap;word-break:break-all}
.sline .mm{font-weight:600;margin-right:6px}
.srcs td{font-size:13px}
/* 해설 */
.expl{margin-top:6px;font-size:13px;line-height:1.55}
.ex-sum{display:flex;gap:6px;align-items:flex-start;background:var(--accent-bg);border-radius:8px;padding:6px 10px;color:var(--text)}
.ex-ic{flex:none;font-size:12px;line-height:1.7}
.ex-det{list-style:none;margin:5px 0 0;padding:0 0 0 4px;display:grid;gap:3px}
.ex-det li{display:flex;gap:8px;align-items:baseline;color:var(--muted);font-size:12.5px}
.ex-det li code{flex:none;max-width:45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline;margin:0;padding:0 6px;border-radius:4px;background:var(--panel2);border:1px solid var(--line);color:var(--text);font-size:11.5px}
.ex-note{margin-top:5px;color:var(--muted);font-size:12.5px}
.ex-chk{margin-top:5px;font-size:12.5px;color:var(--text);border-left:3px solid var(--high);padding:2px 0 2px 8px}
.ex-chk b{color:var(--high);margin-right:4px}
.flow .expl{margin-top:4px}
.flow .ex-sum,.sline .ex-sum{background:none;padding:0;color:var(--muted);font-size:12.5px}
/* 날짜별 막대그래프 */
.hhead{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;margin-bottom:4px}
.hhead h2{margin:0}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-left:auto}
.seg button{border:0;background:none;padding:4px 10px;font-size:12px;color:var(--muted);cursor:pointer}
.seg button+button{border-left:1px solid var(--line)}
.seg button.on{background:var(--accent-bg);color:var(--text);font-weight:600}
.clegend{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:12px;color:var(--muted);margin:6px 0 8px}
.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px;flex:none}
.s-hi{background:var(--crit)}
.s-rest{background:var(--c-rest)}
.smrow{display:grid;grid-template-columns:150px minmax(0,1fr);gap:10px;align-items:end}
.smrow + .smrow{margin-top:4px}
.smlab{display:flex;align-items:center;gap:0;font-size:12.5px;color:var(--text);min-width:0;padding-bottom:2px}
.smlab span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.smlab b{margin-left:auto;font-weight:600;color:var(--muted);font-variant-numeric:tabular-nums;padding-left:6px}
.smrow.main .smlab{font-weight:700}
.smsep{margin:14px 0 6px;font-size:12.5px;font-weight:700;color:var(--muted)}
.smsep small{font-weight:500;color:var(--faint);margin-left:6px}
.hplot{display:grid;grid-template-columns:34px minmax(0,1fr);height:var(--h,100px)}
.hplot.mini .yax span:last-child{display:none}
.hplot.mini .yax span:first-child::before{content:"최대 ";display:none}
.yax{display:flex;flex-direction:column;justify-content:space-between;font-size:10.5px;color:var(--faint);text-align:right;padding-right:6px;font-variant-numeric:tabular-nums;line-height:1}
.bars{display:flex;align-items:stretch;gap:var(--gap,2px);border-bottom:1px solid var(--line);background:linear-gradient(var(--line2),var(--line2)) top/100% 1px no-repeat;min-width:0}
.bcol{flex:1 1 0;min-width:0;display:flex;align-items:flex-end;justify-content:center;cursor:pointer;border-radius:3px 3px 0 0}
.bcol:hover{background:color-mix(in srgb,var(--text) 7%,transparent)}
.bcol.sel{background:color-mix(in srgb,var(--accent) 18%,transparent)}
.bstack{width:100%;max-width:24px;display:flex;flex-direction:column-reverse;gap:2px;border-radius:4px 4px 0 0;overflow:hidden}
.bstack i{display:block;min-height:1px}
.xax{position:relative;height:18px;margin-left:34px;font-size:10.5px;color:var(--faint);white-space:nowrap}
.xax span{position:absolute;top:3px;transform:translateX(-50%)}
.ctip{position:fixed;z-index:300;display:none;pointer-events:none;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:12px;min-width:150px;box-shadow:0 6px 24px rgba(0,0,0,.25);color:var(--text)}
.ctip .th{font-weight:700;margin-bottom:4px;font-family:var(--mono);font-size:11.5px}
.ctip .tr{display:flex;justify-content:space-between;gap:16px;color:var(--muted)}
.ctip .tr b{color:var(--text);font-variant-numeric:tabular-nums}
.ctip .tt{color:var(--text)}
.ctip .tc{margin-top:4px;color:var(--faint);font-size:11px}
@media (max-width:640px){.smrow{grid-template-columns:84px minmax(0,1fr);gap:6px}.smlab b{display:none}.hplot{grid-template-columns:26px minmax(0,1fr)}.xax{margin-left:26px}}
/* 방향 · 파일 */
.thsub{font-weight:500;color:var(--faint);font-size:11px;margin-left:4px}
.dir{white-space:nowrap;font-family:var(--mono);font-size:12.5px;line-height:1.6}
.dir .arr,.arr{font-family:var(--sans);font-weight:700;margin-right:4px}
.dir.in .arr,.arr.in{color:var(--c-auth)}
.dir.out .arr,.arr.out{color:var(--c-lateral)}
.dir.via{color:var(--faint);font-size:11.5px}
.dir.via a{color:var(--muted)}
.badge.self{color:var(--c-session);border-color:color-mix(in srgb,var(--c-session) 45%,transparent);background:color-mix(in srgb,var(--c-session) 10%,transparent)}
.origin{margin-top:5px;font-size:12.5px;color:var(--c-session);cursor:pointer}
.origin:hover{text-decoration:underline}
.origin code{display:inline!important;margin:0!important;white-space:normal}
.origin.warn{cursor:default;text-decoration:none}
.fops{display:flex;flex-wrap:wrap;gap:4px;margin-top:5px}
.fop{display:inline-flex;align-items:center;gap:4px;font-size:11.5px;padding:1px 7px;border-radius:5px;border:1px solid var(--line);background:var(--panel2);color:var(--text);max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-decoration:none!important}
a.fop{cursor:pointer}
.fop .fi{font-size:11px;opacity:.9}
.fop.out{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 40%,transparent);background:var(--crit-bg)}
.fop.del{color:var(--high);border-color:color-mix(in srgb,var(--high) 40%,transparent);background:var(--high-bg)}
.fop.in{color:var(--c-lateral);border-color:color-mix(in srgb,var(--c-lateral) 40%,transparent)}
.fop.exec{color:var(--c-exec);border-color:color-mix(in srgb,var(--c-exec) 40%,transparent)}
.fop.mv,.fop.cp{color:var(--c-fileop);border-color:color-mix(in srgb,var(--c-fileop) 40%,transparent)}
.fop.read,.fop.perm{color:var(--c-privesc)}
.srvbar{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin-bottom:12px}
.srvbar .search{flex:0 1 300px}
.hint{font-size:12.5px;color:var(--muted)}
.dflow{display:grid;grid-template-columns:minmax(0,1fr) 28px minmax(170px,240px) 28px minmax(0,1fr);gap:10px;align-items:center;margin-bottom:6px}
.dh{font-weight:700;font-size:13.5px;display:flex;flex-direction:column}
.dh small{font-weight:500;color:var(--muted);font-size:11.5px}
.dnode{display:flex;justify-content:space-between;gap:8px;align-items:baseline;padding:6px 10px;border:1px solid var(--line);border-radius:8px;margin-top:6px;background:var(--panel2);color:var(--text);text-decoration:none!important;font-size:13px}
.dnode small{color:var(--muted);font-size:11.5px;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dnode.hot{border-color:color-mix(in srgb,var(--crit) 55%,transparent)}
.dnode:hover{border-color:var(--accent)}
.dnone{color:var(--faint);font-size:12.5px;margin-top:8px}
.darrow{text-align:center;font-size:22px;color:var(--faint)}
.dserver{border:2px solid var(--accent);border-radius:12px;padding:14px;text-align:center;background:var(--accent-bg);display:grid;gap:2px}
.dserver small{color:var(--muted);font-size:11.5px}
.dserver .mono{font-weight:700;font-size:14px;word-break:break-all}
.dself{margin-top:6px;font-size:12px;color:var(--c-session)}
@media (max-width:860px){.dflow{grid-template-columns:1fr}.darrow{transform:rotate(90deg)}}
h2.sect{margin:22px 0 10px;display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 8px}
h2.sect small{margin:0}
.cmds{margin-top:8px;display:grid;gap:3px}
.cmds a{display:grid;grid-template-columns:62px minmax(0,1fr);gap:6px;font-size:12px;color:var(--text);text-decoration:none!important;padding:2px 4px;border-radius:5px}
.cmds a:hover{background:var(--panel2)}
.cmds .t{color:var(--muted)}
.cmds code{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fleg{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,max-content) minmax(90px,1fr));gap:4px 8px;margin-top:10px;align-items:center}
.fleg .fl{font-size:12px;color:var(--muted)}
.fcard{margin-bottom:10px}
.fcard.hot{border-color:color-mix(in srgb,var(--crit) 50%,transparent)}
.fcard.focus{outline:2px solid var(--accent)}
.fh{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center}
.fpath{font-weight:700;font-size:14px;word-break:break-all}
.ftl{list-style:none;margin:10px 0 0 6px;padding:0;border-left:2px solid var(--line)}
.ftl li{display:grid;grid-template-columns:110px max-content minmax(0,1fr) max-content;gap:10px;align-items:center;padding:5px 8px 5px 14px;position:relative;cursor:pointer;font-size:13px;border-radius:0 6px 6px 0}
.ftl li::before{content:"";position:absolute;left:-6px;top:50%;margin-top:-5px;width:10px;height:10px;border-radius:50%;background:var(--panel);border:2px solid var(--faint)}
.ftl li:hover{background:var(--panel2)}
.ftl .t{color:var(--muted);font-size:12px}
.ftl .fop{justify-self:start}
.ftl .how{color:var(--muted);min-width:0;word-break:break-all}
.ftl .fwho{color:var(--faint);font-size:12px}
@media (max-width:640px){.ftl li{grid-template-columns:auto minmax(0,1fr)}.ftl .how{grid-column:1/-1}.ftl .fwho{display:none}}
/* 히스토리 */
.hgrid{display:grid;grid-template-columns:260px minmax(0,1fr);gap:16px;align-items:start}
@media (max-width:860px){.hgrid{grid-template-columns:1fr}}
.hlist{position:sticky;top:110px;max-height:calc(100vh - 130px);overflow:auto}
@media (max-width:860px){.hlist{position:static;max-height:none}}
.hfile{display:block;width:100%;text-align:left;background:none;border:1px solid transparent;border-radius:8px;padding:8px 10px;cursor:pointer;margin-bottom:4px}
.hfile:hover{background:var(--panel2)}
.hfile.on{background:var(--accent-bg);border-color:color-mix(in srgb,var(--accent) 40%,transparent)}
.hf-p{font-size:12.5px;word-break:break-all}
.hf-m{font-size:12px;color:var(--muted);margin-top:2px}
.hnotes{font-size:12.5px;color:var(--muted);margin:-4px 0 10px;display:grid;gap:3px}
.hnotes div::before{content:"ⓘ ";color:var(--accent)}
.hcode{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--bg)}
.hl{display:grid;grid-template-columns:44px 112px minmax(0,1fr);gap:10px;padding:5px 12px 5px 0;border-bottom:1px solid var(--line2);font-size:13px}
.hl:last-child{border-bottom:0}
.hl.click{cursor:pointer}
.hl.click:hover{background:var(--panel2)}
.hl.crit{background:var(--crit-bg);box-shadow:inset 3px 0 0 var(--crit)}
.hl.high{background:var(--high-bg);box-shadow:inset 3px 0 0 var(--high)}
.hn{text-align:right;color:var(--faint);font:12px var(--mono);user-select:none}
.ht{color:var(--muted);font:12px var(--mono);white-space:nowrap}
.hc code{white-space:pre-wrap;word-break:break-all;margin-right:6px}
.hc .expl{margin-top:3px}
.hc .ex-sum{background:none;padding:0;color:var(--muted);font-size:12.5px}
@media (max-width:640px){.hl{grid-template-columns:34px minmax(0,1fr)}.ht{display:none}}
.tgl{font-size:12.5px;color:var(--muted);display:flex;gap:5px;align-items:center;white-space:nowrap}
.appendchk{font-size:12.5px;color:var(--text);display:inline-flex;gap:5px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 10px}
/* 가이드 */
.gsteps{margin:0;padding-left:22px;display:grid;gap:6px;font-size:13.5px}
.gcards{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:12px}
@media (max-width:640px){.gcards{grid-template-columns:1fr}}
.g-h{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.badge.ok{color:var(--c-recon);border-color:color-mix(in srgb,var(--c-recon) 45%,transparent)}
.g-files{margin:0 0 10px;font:12px/1.5 var(--mono);color:var(--muted);white-space:pre-wrap}
.g-sec{margin-top:10px;font-size:13px}
.g-t{font-size:12px;font-weight:700;color:var(--muted);margin-bottom:3px}
.g-sec ul{margin:0;padding-left:18px;display:grid;gap:2px}
/* 업로드 */
.dropzone{margin-top:12px;border:2px dashed var(--line);border-radius:12px;padding:34px 16px;text-align:center;color:var(--muted);background:var(--panel2);transition:border-color .15s,background .15s}
.dropzone svg{color:var(--accent)}
.dropzone.disabled{opacity:.55}
.dropzone.disabled svg{color:var(--faint)}
.dz-t{font-size:16px;font-weight:600;color:var(--text);margin-top:8px}
.dz-s{font-size:12.5px;margin-top:4px}
.dropzone .acts{flex-wrap:wrap;margin-top:16px}
.iconbtn.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.iconbtn.primary:hover{color:#fff;filter:brightness(1.1)}
.iconbtn:disabled{opacity:.5;cursor:not-allowed}
body.dragging::after{content:"여기에 놓으면 업로드 후 분석합니다";position:fixed;inset:10px;z-index:100;display:flex;align-items:center;justify-content:center;
  border:3px dashed var(--accent);border-radius:16px;background:color-mix(in srgb,var(--bg) 82%,transparent);color:var(--text);font-size:20px;font-weight:700;pointer-events:none}
@media (max-width:640px){
  .hwrap,nav,main{padding-left:16px;padding-right:16px}
  .flow li{grid-template-columns:58px 12px minmax(0,1fr);gap:8px}
  .daysep{padding-left:78px}
  .sline{grid-template-columns:64px minmax(0,1fr)}
  .sline .c{display:none}
  .cards{grid-template-columns:1fr}
}
</style>
</head>
<body>
<header>
  <div class="hwrap">
    <div class="brand">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M12 8v5"/><path d="M12 16h.01"/></svg>
      침해사고 로그 뷰어
    </div>
    <div class="meta" id="meta"></div>
    <div class="spacer"></div>
    <button class="iconbtn" id="theme" title="테마 전환">테마</button>
  </div>
  <nav id="nav"></nav>
</header>
<main id="main"></main>

<script id="secview-data" type="application/json">__SECVIEW_DATA__</script>
<script>
(function(){
'use strict';
const SEVS=['info','low','med','high','crit'], SEV_L={info:'정보',low:'낮음',med:'중간',high:'높음',crit:'치명'};
const sr = s => SEVS.indexOf(s);
let D, E, CATS, M, bySid, SESS, OFF, HIST, bySrcLine;
const up = { server:null, busy:false, items:[], msg:'', err:'', job:null, append:true };
const hv = { file:0, q:'', risky:false };
const st = { view:'overview', cats:new Set(), minSev:0, q:'', ip:null, user:null, sid:null, dest:null, fpath:null, scope:'all', limit:300, open:new Set(), hideNoise:true, explain:true };
const fv = { q:'', only:false, focus:null };
const ch = { bin:'auto', show:true };
try{ ch.bin = localStorage.getItem('secview-bin') || 'auto'; ch.show = localStorage.getItem('secview-chart')!=='0'; }catch(_){}
let SERVER_IPS = [];
function loadServerIps(){ let v=null; try{ v=localStorage.getItem('secview-server-ip'); }catch(_){} SERVER_IPS = (v!=null && v!=='' ? v : (M.server_ips||[]).join(',')).split(/[\s,]+/).filter(Boolean); }
const isSelf = ip => !!ip && (ip==='localhost' || ip==='::1' || ip.startsWith('127.') || SERVER_IPS.includes(ip));
try{ st.explain = localStorage.getItem('secview-explain')!=='0'; }catch(_){}
function load(data){
  D = data; E = D.events; CATS = D.cats; M = D.meta; OFF = M.tz_offset_min;
  E.forEach((e,i)=>{ e._i=i; });
  bySid = {}; E.forEach(e=>{ if(e.sid) (bySid[e.sid] ||= []).push(e); });
  SESS = {}; D.sessions.forEach(s=>SESS[s.id]=s);
  HIST = D.histories || [];
  bySrcLine = {}; E.forEach(e=>{ if(e.src && e.line) bySrcLine[e.src+':'+e.line] = e; });
  if(M.job) up.job = M.job;
  hv.q = ''; hv.risky = false;
  const risk = HIST.map(h=>h.entries.filter(([ln])=>{ const e=bySrcLine[h.path+':'+ln]; return e && sr(e.sev)>=3; }).length);
  hv.file = risk.length ? risk.indexOf(Math.max(...risk)) : 0;
  loadServerIps(); fv.q=''; fv.focus=null;
  Object.assign(st, { view: E.length ? 'overview' : 'upload', cats:new Set(Object.keys(CATS)), minSev:0, q:'', ip:null, user:null, sid:null, dest:null, fpath:null, scope:'all', range:null, rangeLabel:null, limit:300, open:new Set() });
}
load(JSON.parse(document.getElementById('secview-data').textContent));
try{ const t=localStorage.getItem('secview-theme'); if(t) document.documentElement.dataset.theme=t; }catch(_){}

const $ = s=>document.querySelector(s);
const esc = s => String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function iso(ts){ return new Date((ts+OFF*60)*1000).toISOString(); }
function fmt(ts){ if(ts==null) return '시각 미상'; const s=iso(ts); return s.slice(0,10)+' '+s.slice(11,19); }
function hms(ts){ return ts==null?'—':iso(ts).slice(11,19); }
function day(ts){ return ts==null?'':iso(ts).slice(0,10); }
function dur(a,b){ if(a==null||b==null) return ''; let s=Math.max(0,Math.round(b-a)); const h=Math.floor(s/3600), m=Math.floor(s%3600/60); s%=60; return h?`${h}시간 ${m}분`:m?`${m}분 ${s}초`:`${s}초`; }
const catB = c => `<span class="cat" style="--c:var(--c-${c})">${esc(CATS[c]||c)}</span>`;
const sevB = s => `<span class="sev ${s}">${SEV_L[s]}</span>`;
const HOT = /유출|백도어|무차별|덤프|흔적|변조|UID 0/;
const tagsH = e => (e.tags||[]).map(t=>`<span class="tag${HOT.test(t)?' hot':''}">${esc(t)}</span>`).join('');
const ipH = e => e.ip ? `<a data-act="ip" data-v="${esc(e.ip)}" class="${e.ip_inferred?'inferred':''}" title="${e.ip_inferred?'세션 시간대로 추정한 IP':''}">${esc(e.ip)}</a>` : '';
const isNoise = e => e.sev==='info' && (e.cat==='session' || e.cat==='auth');
function hostBadge(h, kind){
  if(isSelf(h) || kind==='self') return '<span class="badge self">이 서버 자신</span>';
  let k = kind; if(!k){ k = /^\d+\.\d+\.\d+\.\d+$/.test(h) ? (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)?'private':'public') : (h.includes(':')?'public':'domain'); }
  return {private:'<span class="badge">내부망</span>', public:'<span class="badge">외부</span>', domain:'<span class="badge">도메인</span>'}[k]||'';
}
/* IP 칸: ⬇ 들어온 접속의 출발지 / ⬆ 나간 접속의 목적지 / 명령을 실행한 세션의 출발지 */
function ipCell(e){
  let h = '';
  (e.dest||[]).forEach(d=>{ h += `<div class="dir out" title="이 서버에서 나간 연결의 목적지"><span class="arr">⬆</span><a data-act="dest" data-v="${esc(d.host)}">${esc(d.host)}${d.port&&d.port!=='22'?':'+esc(d.port):''}</a>${isSelf(d.host)?' <span class="badge self">자신</span>':''}</div>`; });
  if(e.ip){
    if(e.dir==='in') h += `<div class="dir in" title="이 서버로 들어온 접속의 출발지(접속해 온 쪽)"><span class="arr">⬇</span>${ipH(e)}${isSelf(e.ip)?' <span class="badge self">자신</span>':''}</div>`;
    else h += `<div class="dir via" title="이 명령을 실행한 세션이 어디서 들어왔는지">세션 ⬇ ${ipH(e)}</div>`;
  }
  return h;
}
const whoTxt = e => [e.user ? esc(e.user) : '', (e.dest||[]).map(d=>'⬆ '+esc(d.host)).join(' '), e.ip ? (e.dir==='in'?'⬇ ':'세션 ⬇ ')+esc(e.ip) : ''].filter(Boolean).join(' · ');
function originH(e){
  if(e.origin) return `<div class="origin" data-act="ev" data-v="${e.origin.i}">↪ 실제 출발: 세션 ${esc(e.origin.sid||'?')}${e.origin.ip?` (⬇ ${esc(e.origin.ip)})`:''} 에서 <code>${esc(e.origin.cmd||'')}</code> 실행</div>`;
  if(e.self_origin || (e.kind==='login_ok' && isSelf(e.ip))) return `<div class="origin warn">↪ 서버 안에서 출발한 접속 — 출발지 IP 는 공격자 위치가 아닙니다. 같은 시각의 다른 세션·웹셸·cron 을 확인하세요</div>`;
  return '';
}
const FOP = {'외부로 유출':['out','⇪'],'외부에서 반입':['in','⇩'],'내려받아 저장':['in','⇩'],'삭제':['del','✕'],'이동':['mv','➜'],'이동해 온 곳':['mv','➜'],
  '복사':['cp','⧉'],'복사본':['cp','⧉'],'저장':['save','💾'],'생성':['new','+'],'압축 생성':['zip','▣'],'압축에 포함':['zip','▣'],'압축 해제':['zip','▢'],
  '실행':['exec','▶'],'권한 변경':['perm','🔑'],'시각 위조':['perm','🕒'],'열람':['read','👁']};
function fopB(op, path, to, how){
  const [k, ic] = FOP[op] || ['cp','•'];
  return `<a class="fop ${k}" data-act="file" data-v="${esc(path)}" title="${esc(how||'')}"><span class="fi">${ic}</span>${esc(op)} <span class="mono">${esc(path)}</span>${to?` → <span class="mono">${esc(to)}</span>`:''}</a>`;
}
const filesH = e => e.files ? `<div class="fops">${e.files.map(f=>fopB(f.op, f.path, f.to, f.how)).join('')}</div>` : '';
/* 해설: full=true 면 옵션 설명·확인할 것까지, false 면 요약 문장만 */
function explH(e, full){
  if(!st.explain) return '';
  const x = e.explain, sum = x ? x.summary.join(' ') : '';
  if(!sum && !e.note && !(full && x && x.details.length)) return '';
  let h = '<div class="expl">';
  if(sum || e.note) h += `<div class="ex-sum"><span class="ex-ic" aria-hidden="true">💬</span><span>${esc(sum || e.note)}</span></div>`;
  if(full && x){
    if(x.details.length) h += `<ul class="ex-det">${x.details.map(([t,d])=>`<li><code>${esc(t)}</code><span>${esc(d)}</span></li>`).join('')}</ul>`;
    if(sum && e.note) h += `<div class="ex-note">${esc(e.note)}</div>`;
    if(x.check.length) h += `<div class="ex-chk"><b>확인할 것</b> ${x.check.map(esc).join(' ')}</div>`;
  }
  return h + '</div>';
}
const explText = e => [e.explain ? e.explain.summary.join(' ') : '', e.note||''].filter(Boolean).join(' / ');

/* ── 헤더 ── */
function renderMeta(){
  const r = M.range;
  $('#meta').innerHTML = M.empty ? '<span>로그를 불러오면 분석 결과가 여기에 표시됩니다</span>' : [
    M.hosts.length?`호스트 <b>${esc(M.hosts.join(', '))}</b>`:'',
    r?`기간 <b>${fmt(r[0])}</b> ~ <b>${fmt(r[1])}</b> <span>(${esc(M.tz_label)})</span>`:'',
    `이벤트 <b>${E.length.toLocaleString()}</b>`,
    `생성 ${esc(M.generated)}`
  ].filter(Boolean).map(x=>`<span>${x}</span>`).join('');
}
$('#theme').onclick = ()=>{
  const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
  const nt = cur==='dark'?'light':'dark'; document.documentElement.dataset.theme=nt;
  try{ localStorage.setItem('secview-theme', nt); }catch(_){}
};
if(!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: light)').matches) document.documentElement.dataset.theme='light';

function renderNav(){
  const VIEWS = [['overview','개요'],['timeline','타임라인',E.length],['ips','접속 방향',D.ips.length+(D.outbound||[]).length],['sessions','세션',D.sessions.length],['files','파일 추적',(D.files||[]).length],
    ['history','히스토리',HIST.length],['sources','로그 소스',M.sources.length],['guide','로그 가이드'],['upload','⤒ 로그 불러오기']];
  $('#nav').innerHTML = VIEWS.map(([k,l,n])=>`<button data-act="view" data-v="${k}" class="${st.view===k?'on':''}">${l}${n!=null?`<span class="n">${n.toLocaleString()}</span>`:''}</button>`).join('');
}

/* ── 업로드 ── */
const TZS = (()=>{ const o=-new Date().getTimezoneOffset(); const f=m=>(m<0?'-':'+')+String(Math.floor(Math.abs(m)/60)).padStart(2,'0')+':'+String(Math.abs(m)%60).padStart(2,'0');
  const l=[[f(o),`이 PC 시간대 (UTC${f(o)})`]]; [['+09:00','한국/일본 (UTC+09:00)'],['+00:00','UTC'],['+08:00','UTC+08:00'],['-05:00','UTC-05:00'],['-08:00','UTC-08:00']].forEach(x=>{ if(x[0]!==f(o)) l.push(x); }); return l; })();
up.tz = TZS[0][0];
async function checkServer(){
  if(!/^https?:$/.test(location.protocol)){ up.server=false; return; }
  try{ const r = await fetch('/api/ping',{cache:'no-store'}); const j = await r.json(); up.server = r.ok && j.upload===true; if(j.job) up.job = j.job; }catch(_){ up.server=false; }
  if(st.view==='upload') render();
}
const SUPPORTED = [
  ['auth.log*, secure*', '/var/log', 'SSH 로그인 성공·실패, sudo, 계정 생성, SFTP 전송'],
  ['audit.log*', '/var/log/audit', '실행된 모든 명령(EXECVE), scp 유출, 로그인 세션'],
  ['.bash_history, .zsh_history', '/root, /home/계정', '공격자가 입력한 명령어 (폴더째 올리면 계정 구분)'],
  ['wtmp, btmp', '/var/log', '로그인/로그아웃 기록, 로그인 실패 기록 (바이너리)'],
  ['MySQL general log', '/var/log/mysql', 'mysqldump 덤프, INTO OUTFILE'],
  ['PostgreSQL 로그', '/var/log/postgresql', 'pg_dump 접속, COPY TO 추출'],
  ['xferlog, vsftpd.log', '/var/log', 'FTP 업로드·다운로드'],
  ['passwd', '/etc', 'UID 0 백도어 계정 확인, uid→계정명'],
  ['messages, syslog 등', '/var/log', '이름이 달라도 내용을 보고 SSH/audit/DB 로그를 자동 인식'],
];
function uploadView(){
  const off = up.server===false;
  const status = up.items.length ? `<div class="panel" style="margin-top:16px"><h2>${up.busy?'처리 중…':'결과'} <small>${esc(up.msg)}</small></h2>
    <div class="tablewrap" style="border:0"><table style="min-width:520px"><thead><tr><th>올린 파일</th><th>상태</th><th>인식 결과</th></tr></thead><tbody>
    ${up.items.map(it=>`<tr><td class="mono" style="word-break:break-all">${esc(it.path)} <span style="color:var(--faint)">${fsize(it.size)}</span></td><td style="white-space:nowrap">${esc(it.status)}</td>
      <td style="font-size:12.5px">${it.placed?it.placed.slice(0,6).map(p=>`<div><span class="mono">${esc(p[1])}</span>${p[0]!==it.path?` <span style="color:var(--faint)">← ${esc(p[0])}</span>`:''}</div>`).join('')+(it.placed.length>6?`<div style="color:var(--muted)">외 ${it.placed.length-6}개</div>`:''):''}
      ${it.skipped_count?`<div style="color:var(--muted)">인식 못한 파일 ${it.skipped_count}개 (분석 대상 아님)</div>`:''}${(it.dups||[]).length?`<div style="color:var(--muted)">이미 올린 파일과 내용이 같아 건너뜀 ${it.dups.length}개</div>`:''}${it.error?`<div style="color:var(--crit)">${esc(it.error)}</div>`:''}</td></tr>`).join('')}
    </tbody></table></div></div>` : '';
  return `<div class="panel">
    <h2>로그 불러오기 <small>파일 · 폴더 · 압축파일(zip, tar.gz) 모두 가능</small></h2>
    ${off?`<div class="notes" style="margin:10px 0 14px"><div>지금 화면은 저장된 HTML 파일이라 업로드를 처리할 수 없습니다. 업로드는 분석 서버를 띄워야 동작합니다.</div>
      <pre class="raw" style="margin-top:8px">python secviewer.py --web</pre><div style="margin-top:6px">실행하면 브라우저가 자동으로 열립니다 (직접 열 때는 http://127.0.0.1:8080). 그 화면에 파일을 끌어다 놓으세요.</div></div>`:''}
    <div id="drop" class="dropzone${off?' disabled':''}">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"/></svg>
      <div class="dz-t">${up.busy?esc(up.msg||'처리 중…'):'로그 파일이나 폴더, 압축파일을 여기에 끌어다 놓으세요'}</div>
      <div class="dz-s">수집한 <span class="mono">/var/log</span> 폴더째, 또는 <span class="mono">evidence.tgz</span> 를 그대로 올려도 됩니다 · 다른 탭을 보는 중에도 화면 어디에 놓아도 됩니다</div>
      ${up.job && !off ? `<div class="dz-s" style="margin-top:6px">${up.append?'새로 올린 로그는 <b>지금 결과에 합쳐서</b> 다시 분석합니다. 같은 파일을 두 번 올리면 자동으로 건너뜁니다.':'새로 올리면 <b>지금 결과를 버리고</b> 새로 분석합니다.'}</div>` : ''}
      <div class="acts" style="justify-content:center">
        <button class="iconbtn primary" data-act="pick" ${off||up.busy?'disabled':''}>파일 선택</button>
        <button class="iconbtn" data-act="pickdir" ${off||up.busy?'disabled':''}>폴더 선택</button>
        ${up.job && !off ? `<label class="appendchk"><input type="checkbox" id="append" ${up.append?'checked':''} ${up.busy?'disabled':''}>지금 결과에 추가로 합치기</label>` : ''}
        <select id="tz" ${up.busy?'disabled':''} title="syslog 처럼 시간대가 없는 로그를 어떤 시간대로 해석할지">${TZS.map(([v,l])=>`<option value="${v}" ${up.tz===v?'selected':''}>로그 시간대: ${esc(l)}</option>`).join('')}</select>
      </div>
      <input type="file" id="fin" multiple hidden><input type="file" id="din" webkitdirectory multiple hidden>
    </div>
    ${up.err?`<div class="notes" style="margin-top:12px"><div>${esc(up.err)}</div></div>`:''}
  </div>${status}
  <div class="panel" style="margin-top:16px"><h2>어떤 파일을 올리면 되나요?</h2>
    <div class="tablewrap" style="border:0"><table style="min-width:560px"><thead><tr><th>파일</th><th>서버 위치</th><th>보이는 것</th></tr></thead><tbody>
    ${SUPPORTED.map(r=>`<tr><td class="mono">${esc(r[0])}</td><td class="mono" style="color:var(--muted)">${esc(r[1])}</td><td>${esc(r[2])}</td></tr>`).join('')}</tbody></table></div>
    <p style="font-size:13px;color:var(--muted);margin:12px 0 4px">서버에서 한 번에 모으기 (압축 후 이 화면에 그대로 올리세요):</p>
    <pre class="raw">sudo tar czf evidence.tgz /var/log /root/.*_history /home/*/.*_history /etc/passwd</pre></div>`;
}
const fsize = n => n==null?'':n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(1)+' MB':(n/1073741824).toFixed(2)+' GB';
async function collect(dt){
  const entries = [...(dt.items||[])].map(i=>i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if(!entries.length) return [...dt.files].map(f=>({f, path:f.name}));
  const out = [];
  async function walk(en, prefix){
    if(en.isFile){ const f = await new Promise((res,rej)=>en.file(res,rej)); out.push({f, path:prefix+en.name}); }
    else if(en.isDirectory){ const rd = en.createReader(); let batch;
      do { batch = await new Promise((res,rej)=>rd.readEntries(res,rej)); for(const c of batch) await walk(c, prefix+en.name+'/'); } while(batch.length); }
  }
  for(const en of entries) await walk(en, '');
  return out;
}
async function uploadAll(list){
  if(up.server===false){ st.view='upload'; render(); return; }
  if(up.busy || !list.length) return;
  const job = (up.append && up.job) ? up.job : [...crypto.getRandomValues(new Uint8Array(12))].map(b=>b.toString(16).padStart(2,'0')).join('');
  const appending = job === up.job;
  Object.assign(up, {busy:true, err:'', items:list.map(x=>({path:x.path, size:x.f.size, status:'대기'}))});
  st.view='upload';
  try{
    for(let i=0;i<list.length;i++){
      const it = up.items[i], x = list[i];
      it.status='업로드 중'; up.msg=`업로드 ${i+1}/${list.length}`; render();
      const r = await fetch(`/api/upload?job=${job}&name=${encodeURIComponent(x.path)}&mtime=${x.f.lastModified||0}`, {method:'POST', body:x.f});
      const j = await r.json();
      if(!r.ok) throw new Error(j.error||('HTTP '+r.status));
      Object.assign(it, j); it.status = j.error?'오류':j.placed.length?'인식됨':(j.dups&&j.dups.length)?'이미 올린 파일':'인식 못함';
    }
    if(!appending && !up.items.some(it=>it.placed && it.placed.length)) throw new Error('분석할 수 있는 로그가 없습니다. 아래 표의 파일을 올려주세요.');
    if(appending && !up.items.some(it=>it.placed && it.placed.length)) throw new Error('새로 추가된 로그가 없습니다. (이미 올린 파일이거나 분석 대상이 아닌 파일)');
    up.msg='분석 중…'; render();
    const r = await fetch(`/api/analyze?job=${job}&tz=${encodeURIComponent(up.tz)}&server_ip=${encodeURIComponent(SERVER_IPS.join(','))}`, {method:'POST'});
    if(!r.ok) throw new Error('분석 실패 (HTTP '+r.status+')');
    const data = await r.json();
    up.busy=false; up.msg=`${appending?'기존 결과에 추가 · ':''}올린 파일 ${up.items.length}개 → 전체 이벤트 ${data.events.length.toLocaleString()}건`;
    load(data); renderMeta(); if(!E.length) st.view='upload'; render(); window.scrollTo(0,0);
  }catch(ex){ up.busy=false; up.err = String(ex.message||ex); up.msg=''; render(); }
}
let dragDepth = 0;
document.addEventListener('dragenter', ev=>{ if(![...(ev.dataTransfer?.types||[])].includes('Files')) return; ev.preventDefault(); dragDepth++; document.body.classList.add('dragging'); });
document.addEventListener('dragleave', ()=>{ if(--dragDepth<=0){ dragDepth=0; document.body.classList.remove('dragging'); } });
document.addEventListener('dragover', ev=>{ if([...(ev.dataTransfer?.types||[])].includes('Files')) ev.preventDefault(); });
document.addEventListener('drop', async ev=>{
  if(![...(ev.dataTransfer?.types||[])].includes('Files')) return;
  ev.preventDefault(); dragDepth=0; document.body.classList.remove('dragging');
  const p = collect(ev.dataTransfer);   // webkitGetAsEntry 는 drop 이벤트 안에서 바로 호출해야 함
  uploadAll(await p);
});
document.addEventListener('change', ev=>{
  if(ev.target.id==='fin' || ev.target.id==='din') uploadAll([...ev.target.files].map(f=>({f, path:f.webkitRelativePath||f.name})));
  if(ev.target.id==='tz') up.tz = ev.target.value;
  if(ev.target.id==='append') up.append = ev.target.checked;
});

/* ── 필터 ── */
function searchText(e){ return e._s || (e._s = [e.msg,e.cmd,e.user,e.ip,e.raw,e.src,e.cwd,(e.tags||[]).join(' '),explText(e)].join(' ').toLowerCase()); }
function filtered(ignoreRange){
  const q = st.q.trim().toLowerCase(), rg = ignoreRange ? null : st.range;
  return E.filter(e => (!rg || (e.ts!=null && e.ts>=rg[0] && e.ts<rg[1])) && st.cats.has(e.cat) && sr(e.sev)>=st.minSev && (!st.ip||e.ip===st.ip) && (!st.user||e.user===st.user)
    && (!st.sid||e.sid===st.sid) && (!st.hideNoise || st.ip || st.sid || st.scope==='in' || !isNoise(e)) && (!q || searchText(e).includes(q))
    && (st.scope==='all' || (st.scope==='in' ? e.dir==='in' : st.scope==='out' ? e.dir==='out' : !!e.files))
    && (!st.dest || (e.dest||[]).some(d=>d.host===st.dest)) && (!st.fpath || (e.files||[]).some(f=>f.path===st.fpath || f.to===st.fpath)));
}
function go(view, f){
  Object.assign(st, {view, limit:300}, f||{}); render(); window.scrollTo(0,0);
}

/* ── 개요 ── */
function overview(){
  const ext = D.ips.filter(p=>p.ok>0 && !p.private);
  const fails = D.ips.reduce((a,p)=>a+p.fails,0);
  const cmds = E.filter(e=>e.via && e.cat!=='db' || e.via==='audit' || (e.via && e.cmd && e.cat==='db' && !(e.tags||[]).includes('DB 히스토리'))).length;
  const dbd = E.filter(e=>e.cat==='db' && e.sev==='crit').length;
  const xfer = E.filter(e=>e.cat==='transfer').length;
  const xferOut = E.filter(e=>e.cat==='transfer' && /유출/.test(e.msg+(e.tags||[]).join())).length;
  const pa = E.filter(e=>e.cat==='persist'||e.cat==='antiforensic').length;
  const outHosts = (D.outbound||[]).filter(a=>a.count>0 && !isSelf(a.host));
  const K = [
    ['침입 성공 외부 IP', ext.length, ext.slice(0,3).map(p=>p.ip).join(', ')||'없음', '--crit', ()=>go('ips')],
    ['SSH 로그인 실패', fails, `${D.ips.filter(p=>p.fails>=5).length}개 IP 무차별 대입`, '--c-auth', ()=>go('timeline',{cats:new Set(['auth']),minSev:0})],
    ['실행 명령', cmds, '히스토리 · auditd · sudo', '--c-cmd', ()=>go('timeline',{cats:new Set(['cmd','recon','exec','privesc','persist','antiforensic','db','transfer']),q:'',minSev:0})],
    ['DB 덤프', dbd, 'mysqldump · pg_dump · OUTFILE', '--c-db', ()=>go('timeline',{cats:new Set(['db']),minSev:0})],
    ['파일 전송', xfer, `유출 의심 ${xferOut}건`, '--c-transfer', ()=>go('timeline',{cats:new Set(['transfer']),minSev:0})],
    ['지속성 · 흔적삭제', pa, '계정 · 키 · cron · history', '--c-persist', ()=>go('timeline',{cats:new Set(['persist','antiforensic']),minSev:0})],
    ['⬆ 나간 접속 목적지', outHosts.length, outHosts.slice(0,3).map(a=>a.host).join(', ')||'없음', '--c-lateral', ()=>{ go('ips'); setTimeout(()=>{ const el=document.getElementById('outsec'); if(el) el.scrollIntoView({block:'start'}); window.scrollBy(0,-110); },0); }],
    ['📄 파일 작업', (D.files||[]).length, `유출 ${(D.files||[]).filter(f=>f.flags.includes('유출')).length} · 삭제 ${(D.files||[]).filter(f=>f.flags.some(x=>x.startsWith('삭제'))).length}`, '--c-fileop', ()=>go('files')],
  ];
  window._kpi = K.map(k=>k[4]);
  let h = `<div class="kpis">${K.map((k,i)=>`<button class="kpi${k[1]?'':' zero'}" style="--k:var(${k[3]})" data-act="kpi" data-v="${i}"><div class="l">${k[0]}</div><div class="v">${k[1].toLocaleString()}</div><div class="s">${esc(k[2])}</div></button>`).join('')}</div>`;
  if(M.notes.length) h += `<div class="notes">${M.notes.map(n=>`<div>${esc(n)}</div>`).join('')}</div>`;

  const key = E.filter(e=>sr(e.sev)>=3 && e.ts!=null);
  let lastDay='';
  const flow = key.slice(0,80).map(e=>{
    const d = day(e.ts); const sep = d!==lastDay ? `<div class="daysep">${d}</div>` : ''; lastDay=d;
    return sep+`<li data-act="ev" data-v="${e._i}" style="--c:var(--c-${e.cat})"><div class="t">${hms(e.ts)}</div><div class="dot"></div><div class="b">
      <div>${catB(e.cat)} <span class="m">${esc(e.msg)}</span></div>
      ${e.cmd?`<code>${esc(e.cmd)}</code>`:''}${explH(e,false)}
      ${filesH(e)}${originH(e)}<div class="who">${whoTxt(e)}${e.sid?` · 세션 ${esc(e.sid)}`:''} · ${esc(e.src||'')}</div></div></li>`;
  }).join('');
  h += dateChartOverview();
  h += `<div class="grid2"><section class="panel"><h2>공격 흐름 <small>위험도 높음 이상 ${key.length}건, 시간순</small></h2>
    ${key.length?`<ul class="flow">${flow}</ul>${key.length>80?`<a data-act="kpi-high" class="more iconbtn" style="text-align:center">전체 ${key.length}건 타임라인에서 보기</a>`:''}`:'<div class="empty">높은 위험도 이벤트가 없습니다.</div>'}</section>
    <section><div class="panel" style="margin-bottom:16px"><h2>위험 IP <small>상위 ${Math.min(6,D.ips.length)}</small></h2>${D.ips.slice(0,6).map(ipMini).join('')||'<div class="empty">IP 정보 없음</div>'}</div>
    <div class="panel"><h2>위험 세션</h2>${D.sessions.filter(s=>sr(s.max_sev)>=3).slice(0,8).map(sessMini).join('')||'<div class="empty">없음</div>'}</div></section></div>`;
  return h;
}
function ipMini(p){
  const max = D.ips[0].score||1;
  return `<div style="padding:8px 0;border-bottom:1px solid var(--line2)">
    <div style="display:flex;align-items:center;gap:8px"><a class="mono" data-act="ipcard" data-v="${esc(p.ip)}" style="font-weight:600">${esc(p.ip)}</a>
    ${p.private?'<span class="badge">내부</span>':''}${p.ok&&p.fails>=3?'<span class="badge red">무차별 대입 성공</span>':p.ok?'<span class="badge red">로그인 성공</span>':''}
    <span style="margin-left:auto;font-size:12px;color:var(--muted)">실패 ${p.fails} · 성공 ${p.ok}</span></div>
    <div class="score" style="margin:6px 0 0"><i style="width:${Math.max(3,p.score/max*100)}%"></i></div></div>`;
}
function sessMini(s){
  return `<div style="padding:7px 0;border-bottom:1px solid var(--line2);cursor:pointer" data-act="sess" data-v="${s.id}">
    <div><b class="mono">${esc(s.user||'?')}@${esc(s.ip||'local')}</b> ${sevB(s.max_sev)}</div>
    <div style="font-size:12px;color:var(--muted)">${fmt(s.start)} · ${dur(s.start, s.end ?? s.last)} · 이벤트 ${s.n}</div></div>`;
}

/* ── 날짜별 막대그래프 ── */
function binUnit(evs){
  if(ch.bin !== 'auto') return ch.bin;
  let lo = Infinity, hi = -Infinity;
  for(const e of evs){ if(e.ts==null) continue; if(e.ts<lo) lo=e.ts; if(e.ts>hi) hi=e.ts; }
  return lo!==Infinity && hi-lo <= 3*86400 ? 'hour' : 'day';
}
function makeBins(evs, unit){
  const size = unit==='hour' ? 3600 : 86400, off = OFF*60;
  let lo = Infinity, hi = -Infinity, unknown = 0;
  for(const e of evs){ if(e.ts==null){ unknown++; continue; } const k=Math.floor((e.ts+off)/size); if(k<lo) lo=k; if(k>hi) hi=k; }
  if(lo===Infinity) return {bins:[], unit, unknown};
  if(unit==='hour' && hi-lo > 24*21) return makeBins(evs, 'day');   // 3주가 넘으면 시간별은 너무 촘촘함 → 일별
  if(hi-lo > 1500) lo = hi-1500;
  const bins = [];
  for(let k=lo; k<=hi; k++) bins.push({start:k*size-off, end:(k+1)*size-off, n:0, hi:0, sev:{}, cats:{}});
  for(const e of evs){
    if(e.ts==null) continue;
    const b = bins[Math.floor((e.ts+off)/size)-lo]; if(!b) continue;
    b.n++; if(sr(e.sev)>=3) b.hi++;
    b.sev[e.sev]=(b.sev[e.sev]||0)+1; b.cats[e.cat]=(b.cats[e.cat]||0)+1;
  }
  return {bins, unit, unknown};
}
const binLabel = (b, unit) => unit==='hour' ? `${iso(b.start).slice(5,10)} ${iso(b.start).slice(11,13)}시` : iso(b.start).slice(0,10);
function niceMax(v){ if(v<=4) return Math.max(v,1); const p=Math.pow(10,Math.floor(Math.log10(v))); for(const m of [1,2,2.5,5,10]) if(m*p>=v) return m*p; return v; }
function xAxis(bins, unit){
  if(!bins.length) return '';
  const n = bins.length, want = Math.max(2, Math.min(8, Math.floor(n/2)||2)), step = Math.max(1, Math.ceil(n/want));
  let out = '', lastDay = '';
  for(let i=0;i<n;i+=step){
    const b = bins[i], d = iso(b.start).slice(5,10);
    const t = unit==='hour' ? (d!==lastDay ? `${d} ${iso(b.start).slice(11,13)}시` : `${iso(b.start).slice(11,13)}시`) : d;
    lastDay = d;
    const x = (i+0.5)/n*100;
    out += `<span style="left:${x}%;${i===0?'transform:none;left:0':''}">${t}</span>`;
  }
  return `<div class="xax">${out}</div>`;
}
const CHARTS = {};
/* 막대 한 줄. mode='emph': 위험도 높음 이상(빨강) + 그 외(회색) / mode=카테고리 키: 그 분류 한 색 */
function barRow(id, bins, unit, mode, height){
  let max = 0; for(const b of bins){ const v = mode==='emph' ? b.n : (b.cats[mode]||0); if(v>max) max=v; }
  const top = niceMax(max), n = bins.length, gap = n>160 ? 0 : n>70 ? 1 : 2;
  CHARTS[id] = {bins, unit, mode};
  const sel = st.range;
  const cols = bins.map((b,i)=>{
    const v = mode==='emph' ? b.n : (b.cats[mode]||0);
    const isSel = sel && b.start>=sel[0] && b.end<=sel[1];
    if(!v) return `<div class="bcol${isSel?' sel':''}" data-act="bin" data-c="${id}" data-i="${i}"></div>`;
    const pct = v/top*100;
    const inner = mode==='emph'
      ? `${b.hi?`<i class="s-hi" style="flex:${b.hi}"></i>`:''}${b.n-b.hi?`<i class="s-rest" style="flex:${b.n-b.hi}"></i>`:''}`
      : `<i style="flex:1;background:var(--c-${mode})"></i>`;
    return `<div class="bcol${isSel?' sel':''}" data-act="bin" data-c="${id}" data-i="${i}"><div class="bstack" style="height:max(3px,${pct}%)">${inner}</div></div>`;
  }).join('');
  return `<div class="hplot${mode==='emph'?'':' mini'}" style="--h:${height}px" title="${mode==='emph'?'':'이 줄의 최대 '+max+'건'}"><div class="yax"><span>${top.toLocaleString()}</span><span>0</span></div>
    <div class="bars" style="--gap:${gap}px">${cols}</div></div>`;
}
function unitSeg(){
  return `<div class="seg" role="group" aria-label="막대 단위">${[['auto','자동'],['day','일별'],['hour','시간별']].map(([v,l])=>`<button data-act="binunit" data-v="${v}" class="${ch.bin===v?'on':''}">${l}</button>`).join('')}</div>`;
}
const LEGEND_EMPH = `<div class="clegend"><span><i class="sw s-hi"></i>위험도 높음 이상 (치명·높음)</span><span><i class="sw s-rest"></i>그 외</span></div>`;
/* 개요: 전체 + 분류별 작은 막대(small multiples) */
function dateChartOverview(){
  const evs = E.filter(e=>!isNoise(e));
  const {bins, unit, unknown} = makeBins(evs, binUnit(evs));
  if(!bins.length) return '';
  const cats = Object.keys(CATS).filter(c=>bins.some(b=>b.cats[c]));
  const busiest = bins.reduce((a,b)=>b.n>a.n?b:a, bins[0]);
  const rows = cats.map(c=>{
    const tot = bins.reduce((a,b)=>a+(b.cats[c]||0),0);
    return `<div class="smrow"><div class="smlab"><i class="sw" style="background:var(--c-${c})"></i><span>${esc(CATS[c])}</span><b>${tot.toLocaleString()}</b></div>${barRow('sm-'+c, bins, unit, c, 34)}</div>`;
  }).join('');
  return `<section class="panel hist" style="margin-bottom:16px">
    <div class="hhead"><h2>${unit==='hour'?'시간별':'날짜별'} 발생 <small>가장 많은 때: ${binLabel(busiest, unit)} · ${busiest.n.toLocaleString()}건${unknown?` · 시각 미상 ${unknown}건 제외`:''} · 접속 잡음 제외</small></h2>${unitSeg()}</div>
    ${LEGEND_EMPH}
    <div class="smrow main"><div class="smlab"><span>전체</span><b>${evs.length.toLocaleString()}</b></div>${barRow('ov-main', bins, unit, 'emph', 110)}</div>
    <div class="smsep">분류별 <small>각 줄은 그 분류 안에서의 최댓값 기준 · 막대를 누르면 그 기간의 타임라인</small></div>
    ${rows}
    <div class="smrow"><div class="smlab"></div>${xAxis(bins, unit)}</div>
  </section>`;
}
/* 타임라인: 현재 필터 기준 (기간 선택은 강조만) */
function dateChartTimeline(){
  const evs = filtered(true);
  const {bins, unit, unknown} = makeBins(evs, binUnit(evs));
  if(!bins.length) return '';
  if(!ch.show) return `<div class="toolbar"><button class="iconbtn" data-act="chartshow">▤ ${unit==='hour'?'시간별':'날짜별'} 그래프 보기</button></div>`;
  return `<section class="panel hist" style="margin-bottom:10px;padding:12px 16px">
    <div class="hhead"><h2 style="margin:0">${unit==='hour'?'시간별':'날짜별'} 건수 <small>지금 필터 기준${unknown?` · 시각 미상 ${unknown}건 제외`:''} · 막대를 누르면 그 기간만</small></h2>${unitSeg()}<button class="iconbtn" data-act="chartshow" title="그래프 접기">접기</button></div>
    ${LEGEND_EMPH}
    <div class="smrow main"><div class="smlab"></div>${barRow('tl-main', bins, unit, 'emph', 90)}</div>
    <div class="smrow"><div class="smlab"></div>${xAxis(bins, unit)}</div></section>`;
}
/* 막대 툴팁 */
const TIP = document.createElement('div'); TIP.className = 'ctip'; TIP.setAttribute('role','tooltip'); document.body.appendChild(TIP);
document.addEventListener('mousemove', ev=>{
  const c = ev.target.closest && ev.target.closest('.bcol');
  if(!c){ TIP.style.display='none'; return; }
  const C = CHARTS[c.dataset.c]; if(!C){ TIP.style.display='none'; return; }
  const b = C.bins[+c.dataset.i];
  let body;
  if(C.mode==='emph'){
    const sev = SEVS.slice().reverse().filter(x=>b.sev[x]).map(x=>`<div class="tr"><span>${SEV_L[x]}</span><b>${b.sev[x]}</b></div>`).join('');
    const top = Object.entries(b.cats).sort((a,b)=>b[1]-a[1]).slice(0,4).map(([k,n])=>`${esc(CATS[k])} ${n}`).join(' · ');
    body = `<div class="tr tt"><span>총</span><b>${b.n.toLocaleString()}건</b></div>${sev}${top?`<div class="tc">${top}</div>`:''}`;
  } else {
    body = `<div class="tr tt"><span>${esc(CATS[C.mode])}</span><b>${(b.cats[C.mode]||0).toLocaleString()}건</b></div>`;
  }
  TIP.innerHTML = `<div class="th">${binLabel(b, C.unit)}${C.unit==='hour'?' ~ '+iso(b.end).slice(11,13)+'시':''}</div>${body}<div class="tc">클릭: 이 기간 타임라인</div>`;
  TIP.style.display = 'block';
  const w = TIP.offsetWidth, h = TIP.offsetHeight;
  let x = ev.clientX + 14, y = ev.clientY - h - 10;
  if(x + w > innerWidth - 8) x = ev.clientX - w - 14;
  if(y < 8) y = ev.clientY + 16;
  TIP.style.left = x+'px'; TIP.style.top = y+'px';
});
document.addEventListener('scroll', ()=>{ TIP.style.display='none'; }, true);

/* ── 타임라인 ── */
function timeline(){
  const cnt = {}; E.forEach(e=>cnt[e.cat]=(cnt[e.cat]||0)+1);
  const rows = filtered();
  const pills = [['ip','IP'],['user','사용자'],['sid','세션'],['dest','⬆ 목적지'],['fpath','파일']].filter(([k])=>st[k]).map(([k,l])=>`<span class="pill">${l}: <b class="mono">${esc(st[k])}</b><button data-act="clr" data-v="${k}" aria-label="필터 해제">×</button></span>`).join('')
    + (st.range ? `<span class="pill">기간: <b class="mono">${esc(st.rangeLabel||'')}</b><button data-act="clrrange" aria-label="기간 필터 해제">×</button></span>` : '');
  let h = `<div class="toolbar">
    <input class="search" id="q" placeholder="검색: 명령어, IP, 계정, 파일 경로, 원본 로그…" value="${esc(st.q)}">
    <select id="scope" title="접속 방향 / 파일 작업으로 좁혀 보기">${[['all','모든 이벤트'],['in','⬇ 들어온 접속 (다른 곳 → 이 서버)'],['out','⬆ 나간 접속 (이 서버 → 다른 곳)'],['file','📄 파일 작업 (저장·이동·삭제·전송)']].map(([v,l])=>`<option value="${v}" ${st.scope===v?'selected':''}>${l}</option>`).join('')}</select>
    <select id="sev">${SEVS.map((s,i)=>`<option value="${i}" ${st.minSev===i?'selected':''}>${i?SEV_L[s]+' 이상':'모든 위험도'}</option>`).join('')}</select>
    <label style="font-size:12.5px;color:var(--muted);display:flex;gap:5px;align-items:center"><input type="checkbox" id="noise" ${st.hideNoise?'checked':''}>접속 잡음 숨김</label>
    <label style="font-size:12.5px;color:var(--muted);display:flex;gap:5px;align-items:center"><input type="checkbox" id="explain" ${st.explain?'checked':''}>명령어 해설 보기</label>
    <button class="iconbtn" data-act="csv">CSV 내보내기</button></div>
  <div class="chips"><button class="chip" data-act="allcats" style="--c:var(--muted)">${st.cats.size===Object.keys(CATS).length?'모두 해제':'모두 선택'}</button>
    ${Object.keys(CATS).map(c=>`<button class="chip ${st.cats.has(c)?'on':''}" data-act="cat" data-v="${c}" style="--c:var(--c-${c})"><i></i>${esc(CATS[c])}<span class="n">${cnt[c]||0}</span></button>`).join('')}</div>
  ${dateChartTimeline()}
  <div class="toolbar">${pills}<span class="count">${rows.length.toLocaleString()}건${rows.length>st.limit?` 중 ${st.limit.toLocaleString()}건 표시`:''}</span></div>`;
  if(!rows.length) return h+`<div class="tablewrap"><div class="empty">조건에 맞는 이벤트가 없습니다.</div></div>`;
  h += `<div class="tablewrap"><table><thead><tr><th>시각 (${esc(M.tz_label)})</th><th>위험</th><th>분류</th><th>사용자</th><th>IP <span class="thsub">⬇들어옴 ⬆나감</span></th><th>내용</th><th>출처</th></tr></thead><tbody>`;
  h += rows.slice(0,st.limit).map(rowH).join('');
  h += `</tbody></table></div>`;
  if(rows.length>st.limit) h += `<button class="iconbtn more" data-act="more">더 보기 (+500)</button>`;
  return h;
}
function rowH(e){
  const open = st.open.has(e._i);
  return `<tr class="ev ${e.sev}${open?' open':''}" data-act="row" data-v="${e._i}">
    <td class="t">${fmt(e.ts)}</td><td>${sevB(e.sev)}</td><td>${catB(e.cat)}</td>
    <td>${e.user?`<a data-act="user" data-v="${esc(e.user)}">${esc(e.user)}</a>`:''}</td>
    <td class="ipc">${ipCell(e)}</td>
    <td class="m"><div class="msg">${esc(e.msg)}</div>${e.cmd?`<code>${esc(e.cmd)}</code>`:''}${originH(e)}${filesH(e)}${explH(e,true)}<div>${tagsH(e)}</div></td>
    <td class="src">${esc(e.src||'')}${e.line?':'+e.line:''}</td></tr>`
    + (open?`<tr class="detail"><td colspan="7">${detailH(e)}</td></tr>`:'');
}
function detailH(e){
  const s = e.sid && SESS[e.sid];
  const kv = [
    ['출처', `<span class="mono">${esc(e.src||'')}${e.line?':'+e.line:''}</span>`],
    s?['세션', `<a data-act="sess" data-v="${s.id}">${esc(s.id)} — ${esc(s.user||'?')}@${esc(s.ip||'local')} (${fmt(s.start)} 시작)</a>`]:null,
    e.cwd?['작업 경로', `<span class="mono">${esc(e.cwd)}</span>`]:null,
    e.pid?['PID', `<span class="mono">${esc(e.pid)}</span>`]:null,
    e.exe?['실행 파일', `<span class="mono">${esc(e.exe)}</span>`]:null,
    e.ses?['audit 세션', `<span class="mono">ses=${esc(e.ses)}</span>`]:null,
    e.path?['파일', `<span class="mono">${esc(e.path)}</span>`]:null,
    e.count?['횟수', `${e.count}회${e.until?` (마지막 ${fmt(e.until)})`:''}`]:null,
    e.ip_inferred?['참고', '이 IP 는 로그에 직접 기록된 값이 아니라, 같은 시간대에 열려 있던 유일한 외부 SSH 세션으로 추정한 값입니다.']:null,
  ].filter(Boolean);
  return `<dl class="kv">${kv.map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>${e.raw?`<div style="margin-top:10px"><pre class="raw">${esc(e.raw)}</pre></div>`:''}`;
}
function csv(){
  const rows = filtered();
  const q = v => '"' + String(v==null?'':v).replace(/"/g,'""') + '"';
  const out = ['시각,위험,분류,사용자,방향,IP,목적지,세션,내용,명령/대상,파일 작업,해설,태그,출처'].concat(rows.map(e=>[fmt(e.ts),SEV_L[e.sev],CATS[e.cat],e.user,e.dir==='in'?'들어옴':e.dir==='out'?'나감':'',e.ip,(e.dest||[]).map(d=>d.host).join(' '),e.sid,e.msg,e.cmd,(e.files||[]).map(f=>f.op+' '+f.path+(f.to?' → '+f.to:'')).join(' | '),explText(e),(e.tags||[]).join(' | '),(e.src||'')+(e.line?':'+e.line:'')].map(q).join(',')));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['\ufeff'+out.join('\r\n')],{type:'text/csv'}));
  a.download = 'secview_events.csv'; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
}

/* ── 접속 방향 ── */
function inCard(p, max){
  const self = isSelf(p.ip), hot = p.ok && !p.private && !self;
  const cats = Object.entries(p.cats).sort((a,b)=>b[1]-a[1]).map(([c,n])=>`${catB(c)} <span style="font-size:12px;color:var(--muted)">${n}</span>`).join(' ');
  return `<div class="card${hot?' hot':''}" id="ip-${esc(p.ip)}">
    <h3><span class="arr in">⬇</span>${esc(p.ip)} ${hostBadge(p.ip, p.private?'private':'public')}${!self&&p.ok&&p.fails>=3?'<span class="badge red">무차별 대입 성공</span>':!self&&p.ok&&!p.private?'<span class="badge red">외부에서 로그인 성공</span>':p.ok?'<span class="badge">로그인 성공</span>':p.fails>=5?'<span class="badge">무차별 대입</span>':''}</h3>
    ${self?'<div class="row" style="color:var(--c-session)">이 서버 안에서 출발한 접속입니다. 실제로 누가 시작했는지는 세션 화면의 ↪ 표시(직전에 ssh 를 실행한 세션)를 확인하세요.</div>':''}
    <div class="score" title="위험 점수 ${p.score}"><i style="width:${Math.max(2,p.score/max*100)}%"></i></div>
    <div class="stats"><div><b>${p.fails.toLocaleString()}</b><span>로그인 실패</span></div><div><b style="${p.ok&&!self?'color:var(--crit)':''}">${p.ok}</b><span>로그인 성공</span></div><div><b>${p.sessions.length}</b><span>세션</span></div></div>
    ${p.ok_users.length?`<div class="row">성공 계정 <b class="mono" style="${self?'':'color:var(--crit)'}">${p.ok_users.map(esc).join(', ')}</b></div>`:''}
    ${p.tried.length?`<div class="row">시도 계정 <b class="mono">${p.tried.slice(0,8).map(([u,n])=>esc(u)+(n?`(${n})`:'')).join(', ')}${p.tried.length>8?' …':''}</b></div>`:''}
    <div class="row">최초 <b class="mono">${fmt(p.first)}</b></div><div class="row">최종 <b class="mono">${fmt(p.last)}</b></div>
    ${cats?`<div class="row" style="margin-top:8px">${cats}</div>`:''}
    <div class="acts"><button class="iconbtn" data-act="ip" data-v="${esc(p.ip)}">타임라인</button>${p.sessions.length?`<button class="iconbtn" data-act="ipsess" data-v="${esc(p.ip)}">세션 ${p.sessions.length}개</button>`:''}</div></div>`;
}
function outCard(a){
  return `<div class="card${sr(a.sev)>=4&&!isSelf(a.host)?' hot':''}" id="dest-${esc(a.host)}">
    <h3><span class="arr out">⬆</span>${esc(a.host)} ${hostBadge(a.host, a.kind)} ${a.count?sevB(a.sev):''}</h3>
    <div class="row" style="margin-top:8px">한 일 ${a.whats.map(([w,n])=>`<span class="tag${/유출|업로드|리버스|터널/.test(w)?' hot':''}">${esc(w)}${n>1?' ×'+n:''}</span>`).join('')||'<span class="tag">명령 기록 없음</span>'}</div>
    ${a.ports.length?`<div class="row">포트 <b class="mono">${a.ports.map(esc).join(', ')}</b></div>`:''}
    ${a.users.length?`<div class="row">실행 계정 <b class="mono">${a.users.map(esc).join(', ')}</b></div>`:''}
    ${a.src_ips.length?`<div class="row">명령을 친 세션의 출발지 <b class="mono">⬇ ${a.src_ips.map(esc).join(', ')}</b></div>`:''}
    ${a.first!=null?`<div class="row">최초 <b class="mono">${fmt(a.first)}</b>${a.last!==a.first?` · 최종 <b class="mono">${fmt(a.last)}</b>`:''}</div>`:''}
    ${a.known_by.length?`<div class="row">known_hosts 에 등록됨 (${a.known_by.map(esc).join(', ')} 계정) — 이 서버에서 SSH 로 접속한 적 있는 곳</div>`:''}
    ${a.events.length?`<div class="cmds">${a.events.slice(0,4).map(i=>`<a data-act="ev" data-v="${i}"><span class="mono t">${E[i].ts!=null?hms(E[i].ts):'시각 미상'}</span><code>${esc(E[i].cmd||'')}</code></a>`).join('')}${a.events.length>4?`<div class="row">외 ${a.events.length-4}건</div>`:''}</div>
      <div class="acts"><button class="iconbtn" data-act="dest" data-v="${esc(a.host)}">타임라인</button></div>`:''}</div>`;
}
function ips(){
  const ins = D.ips, outs = D.outbound||[];
  const max = (ins[0]&&ins[0].score)||1;
  const selfIn = E.filter(e=>e.kind==='login_ok' && (e.self_origin || isSelf(e.ip))).length;
  const topIn = ins.filter(p=>!isSelf(p.ip)).slice(0,6), topOut = outs.filter(a=>!isSelf(a.host)).slice(0,6);
  const hashed = (D.known_hosts||[]).reduce((n,k)=>n+k.hashed,0);
  return `<div class="panel srvbar"><label for="srvip"><b>이 서버 IP</b></label>
      <input id="srvip" class="search" value="${esc(SERVER_IPS.join(', '))}" placeholder="예: 10.10.40.95 (쉼표로 여러 개)">
      <span class="hint">${(M.server_ips_auto||[]).length?`로그에서 자동 감지: <span class="mono">${esc(M.server_ips_auto.join(', '))}</span> · `:''}이 IP 로 들어온 접속은 "서버 자신에서 출발"로 따로 표시합니다</span></div>
    <div class="panel dflow">
      <div class="dcol"><div class="dh">⬇ 들어온 접속<small>다른 곳 → 이 서버 (auth.log·wtmp·audit)</small></div>
        ${topIn.map(p=>`<a class="dnode${p.ok&&!p.private?' hot':''}" data-act="ipcard" data-v="${esc(p.ip)}"><span class="mono">${esc(p.ip)}</span><small>${p.ok?`로그인 성공 ${p.ok}`:`실패 ${p.fails}`}</small></a>`).join('')||'<div class="dnone">없음</div>'}</div>
      <div class="darrow" aria-hidden="true">→</div>
      <div class="dcol"><div class="dserver"><small>이 서버</small><div class="mono">${esc(SERVER_IPS.join(', ')||M.hosts.join(', ')||'IP 미입력')}</div>${M.hosts.length&&SERVER_IPS.length?`<small>${esc(M.hosts.join(', '))}</small>`:''}
        ${selfIn?`<div class="dself">↻ 자기 자신에게 다시 접속 ${selfIn}회</div>`:''}</div></div>
      <div class="darrow" aria-hidden="true">→</div>
      <div class="dcol"><div class="dh">⬆ 나간 접속<small>이 서버 → 다른 곳 (명령·known_hosts)</small></div>
        ${topOut.map(a=>`<a class="dnode${sr(a.sev)>=4?' hot':''}" data-act="destcard" data-v="${esc(a.host)}"><span class="mono">${esc(a.host)}</span><small>${esc(a.whats.map(w=>w[0]).join(', ')||'known_hosts')}</small></a>`).join('')||'<div class="dnone">기록 없음</div>'}</div>
    </div>
    <h2 class="sect"><span class="arr in">⬇</span> 들어온 접속 <small>다른 곳에서 이 서버로 접속해 온 출발지 IP — auth.log 의 "from IP", wtmp, audit 로그인 기록</small></h2>
    ${ins.length?`<div class="cards">${ins.map(p=>inCard(p,max)).join('')}</div>`:'<div class="panel empty">들어온 접속 기록이 없습니다.</div>'}
    <h2 class="sect" id="outsec"><span class="arr out">⬆</span> 나간 접속 <small>이 서버에서 다른 곳으로 연결한 목적지 — auth.log 에는 남지 않아 실행한 명령(히스토리·auditd)과 known_hosts 로 찾았습니다</small></h2>
    ${outs.length?`<div class="cards">${outs.map(outCard).join('')}</div>`:'<div class="panel empty">이 서버에서 밖으로 나간 연결 기록이 없습니다. (ssh·scp·curl·wget·nc 명령이나 known_hosts 가 있으면 표시됩니다)</div>'}
    ${hashed?`<p class="hint" style="margin-top:10px">known_hosts 에서 해시로 저장된 항목 ${hashed}개는 주소를 알 수 없습니다 (HashKnownHosts 설정). 서버에서 <span class="mono">ssh-keygen -F 의심IP</span> 로 특정 주소가 있는지는 확인할 수 있습니다.</p>`:''}`;
}

/* ── 파일 추적 ── */
function filesView(){
  const F = D.files||[];
  if(!F.length) return '<div class="panel empty">파일 작업 기록이 없습니다. (명령 기록·SFTP/FTP 로그에서 저장·이동·삭제·전송을 찾습니다)</div>';
  const q = fv.q.trim().toLowerCase();
  let list = F.map((f,i)=>({f,i}));
  if(fv.only) list = list.filter(({f})=>f.flags.length && f.flags.some(x=>/유출|삭제/.test(x)));
  if(q) list = list.filter(({f})=>f.path.toLowerCase().includes(q) || f.ops.some(o=>(o.how+' '+(o.to||'')+' '+(o.from||'')).toLowerCase().includes(q)));
  return `<div class="panel" style="margin-bottom:12px"><h2>파일 추적 <small>파일마다 무슨 일이 있었는지 시간순으로 — 생성·저장 → 압축 → 이동·복사 → 외부 전송 → 삭제</small></h2>
      <div class="toolbar" style="margin:0"><input class="search" id="fq" placeholder="파일 경로 검색 (예: /tmp, .sql, authorized_keys)" value="${esc(fv.q)}">
      <label class="tgl"><input type="checkbox" id="fonly" ${fv.only?'checked':''}>유출·삭제된 파일만</label><span class="count">${list.length}개</span></div>
      <div class="fleg">${Object.entries({'외부로 유출':'서버 밖으로 나감','외부에서 반입':'밖에서 들어옴','저장':'파일로 저장','이동':'옮김/이름 변경','복사':'복사','삭제':'지움','압축 생성':'묶음','실행':'실행','권한 변경':'권한·시각 변경','열람':'민감 파일 열람'}).map(([k,v])=>{ const [c,ic]=FOP[k]; return `<span class="fop ${c}"><span class="fi">${ic}</span>${esc(k)}</span><span class="fl">${esc(v)}</span>`; }).join('')}</div></div>
    ${list.map(({f,i})=>`<div class="panel fcard${f.flags.includes('유출')?' hot':''}${fv.focus===f.path?' focus':''}" id="file-${i}">
      <div class="fh"><span class="mono fpath">${esc(f.path)}</span>${f.flags.map(x=>`<span class="badge${/유출|삭제됨/.test(x)?' red':''}">${esc(x)}</span>`).join('')}${sevB(f.sev)}
        <button class="iconbtn" data-act="fpath" data-v="${esc(f.path)}" style="margin-left:auto">타임라인</button></div>
      <ol class="ftl">${f.ops.map(o=>{ const [c,ic]=FOP[o.op]||['cp','•']; return `<li data-act="ev" data-v="${o.i}">
        <span class="t mono">${o.ts!=null?fmt(o.ts).slice(5):'시각 미상'}</span><span class="fop ${c}"><span class="fi">${ic}</span>${esc(o.op)}</span>
        <span class="how">${esc(o.how)}${o.to?` → <span class="mono">${esc(o.to)}</span>`:''}${o.from?` ← <span class="mono">${esc(o.from)}</span>`:''}</span>
        <span class="fwho">${esc(o.user||'')}${o.sid?' · '+esc(o.sid):''}</span></li>`; }).join('')}</ol></div>`).join('') || '<div class="panel empty">조건에 맞는 파일이 없습니다.</div>'}`;
}

/* ── 세션 ── */
function sessions(){
  let list = D.sessions;
  if(st.ip) list = list.filter(s=>s.ip===st.ip);
  if(!list.length) return '<div class="panel empty">세션 정보가 없습니다. (auth.log / wtmp / audit 의 로그인 기록으로 만듭니다)</div>';
  const head = st.ip?`<div class="toolbar"><span class="pill">IP: <b class="mono">${esc(st.ip)}</b><button data-act="clr" data-v="ip">×</button></span></div>`:'';
  return head + list.map(s=>{
    const es = (bySid[s.id]||[]).filter(e=>!isNoise(e) || e.kind==='login_ok');
    const hot = sr(s.max_sev)>=4;
    const cats = Object.entries(s.cats).filter(([c])=>c!=='auth').map(([c,n])=>`${catB(c)}<span style="font-size:12px;color:var(--muted);margin:0 6px 0 3px">${n}</span>`).join('');
    return `<details class="sess${hot?' hot':''}" id="sess-${s.id}" ${hot||st.sid===s.id?'open':''}>
      <summary><span class="mono" style="color:var(--faint)">${s.id}</span><span class="who">${esc(s.user||'?')}@<span title="이 세션이 들어온 출발지">⬇${esc(s.ip||'local')}</span></span>${sevB(s.max_sev)}
      ${s.self_origin||isSelf(s.ip)?'<span class="badge self">서버 내부에서 출발</span>':''}${s.origin_sid?`<a class="badge self" data-act="sess" data-v="${s.origin_sid}">↪ ${s.origin_sid} 에서 다시 접속</a>`:''}
      <span class="when">${fmt(s.start)} → ${s.end!=null?hms(s.end):'종료 기록 없음'} · ${dur(s.start, s.end ?? s.last)}</span>
      ${s.method?`<span class="badge">${esc(s.method)}</span>`:''}${s.fails_before>=3?`<span class="badge red">직전 실패 ${s.fails_before}회</span>`:''}
      <span style="font-size:12px;color:var(--faint)">근거: ${esc(s.sources.join(', '))}</span><span>${cats}</span></summary>
      <div class="body">${es.map(e=>`<div class="sline" data-act="ev" data-v="${e._i}"><span class="t">${hms(e.ts)}</span><span class="c">${catB(e.cat)}</span>
        <span><span class="mm" style="color:var(--${e.sev==='info'?'muted':e.sev})">${esc(e.msg)}</span>${e.cmd?`<code>${esc(e.cmd)}</code>`:''}${(e.dest||[]).length?`<div class="dir out" style="font-size:12px"><span class="arr">⬆</span>${e.dest.map(d=>esc(d.host)+' '+esc(d.what)).join(', ')}</div>`:''}${filesH(e)}${explH(e,false)}</span></div>`).join('')||'<div class="empty">연결된 이벤트 없음</div>'}</div></details>`;
  }).join('');
}

/* ── 히스토리 원문 ── */
const HIST_TAMPER = /history\s+-[cw]|unset\s+HISTFILE|HISTFILE=\/dev\/null|HISTSIZE=0|set\s+\+o\s+history/;
function historyView(){
  if(!HIST.length) return `<div class="panel empty">셸 히스토리 파일이 없습니다.<br><span style="font-size:13px">/root/.bash_history, /home/계정/.bash_history 를 올리면 여기서 원문을 줄 단위로 볼 수 있습니다.</span></div>`;
  const h = HIST[Math.min(hv.file, HIST.length-1)];
  const q = hv.q.trim().toLowerCase();
  const list = HIST.map((x,i)=>{
    const risky = x.entries.filter(([ln])=>{ const e=bySrcLine[x.path+':'+ln]; return e && sr(e.sev)>=3; }).length;
    return `<button class="hfile${i===hv.file?' on':''}" data-act="hfile" data-v="${i}">
      <div class="mono hf-p">${esc(x.path)}</div>
      <div class="hf-m"><b>${esc(x.user)}</b> · ${x.entries.length.toLocaleString()}줄${risky?` · <span style="color:var(--crit)">위험 ${risky}</span>`:''}${x.db?' · DB 기록':''}</div></button>`;
  }).join('');
  const notes = [];
  if(!h.entries.length) notes.push('파일이 비어 있습니다. 공격자가 기록을 지웠거나(> ~/.bash_history), 기록이 저장되지 않게 했을 수 있습니다.');
  else if(!h.with_ts) notes.push('이 파일에는 실행 시각이 없습니다(HISTTIMEFORMAT 미설정). 명령의 순서만 알 수 있고, 언제 실행했는지는 auditd·auth.log 와 맞춰 봐야 합니다.');
  else if(h.with_ts < h.entries.length) notes.push(`일부 줄(${h.entries.length-h.with_ts}개)에만 시각이 없습니다. 시각 기록 설정 전의 오래된 명령입니다.`);
  const tamper = h.entries.find(([,,c])=>HIST_TAMPER.test(c));
  if(tamper) notes.push(`${tamper[0]}번째 줄에서 기록을 지우거나 끄는 명령(${tamper[2]})이 실행됐습니다. 그 뒤에 친 명령은 이 파일에 없을 수 있으니 auditd 기록과 비교하세요.`);
  notes.push('bash 는 보통 로그아웃할 때 기록을 파일에 씁니다. 접속이 강제로 끊기면 마지막 명령들이 빠질 수 있습니다.');
  let rows = h.entries.map(([ln,ts,cmd])=>({ln,ts,cmd,e:bySrcLine[h.path+':'+ln]}));
  if(hv.risky) rows = rows.filter(r=>r.e && sr(r.e.sev)>=2);
  if(q) rows = rows.filter(r=>(r.cmd+' '+(r.e?explText(r.e):'')).toLowerCase().includes(q));
  const shown = rows.slice(0, 3000);
  return `<div class="hgrid"><aside class="panel hlist"><h2>히스토리 파일 <small>${HIST.length}개</small></h2>${list}</aside>
    <section class="panel" style="min-width:0">
      <h2 class="mono" style="word-break:break-all">${esc(h.path)} <small>${esc(h.user)} 계정 · ${h.entries.length.toLocaleString()}줄${h.mtime?` · 파일 수정 ${fmt(h.mtime)}`:''}</small></h2>
      <div class="hnotes">${notes.map(n=>`<div>${esc(n)}</div>`).join('')}</div>
      <div class="toolbar"><input class="search" id="hq" placeholder="이 파일에서 검색 (명령, 해설)" value="${esc(hv.q)}">
        <label class="tgl"><input type="checkbox" id="hrisky" ${hv.risky?'checked':''}>위험한 줄만</label>
        <label class="tgl"><input type="checkbox" id="hexplain" ${st.explain?'checked':''}>해설 보기</label>
        <span class="count">${rows.length.toLocaleString()}줄</span></div>
      <div class="hcode">${shown.map(({ln,ts,cmd,e})=>`<div class="hl${e?' '+e.sev:''}${e?' click':''}" ${e?`data-act="hline" data-v="${e._i}"`:''}>
        <span class="hn">${ln}</span><span class="ht">${ts!=null?fmt(ts).slice(5):''}</span>
        <div class="hc"><code>${esc(cmd)}</code>${e && sr(e.sev)>=1?` ${sevB(e.sev)} ${catB(e.cat)}`:''}${e?explH(e,false):''}</div></div>`).join('')
        || '<div class="empty">조건에 맞는 줄이 없습니다.</div>'}</div>
      ${rows.length>shown.length?`<div class="empty">앞의 ${shown.length.toLocaleString()}줄만 표시했습니다. 검색으로 좁혀 보세요.</div>`:''}
    </section></div>`;
}

/* ── 로그 가이드 ── */
const GUIDE = [
  { k:'auth', name:'SSH·계정 로그', files:'/var/log/auth.log* (Ubuntu·Debian)\n/var/log/secure* (RHEL·CentOS·Rocky)', kind:'SSH/계정', prio:1,
    what:'SSH 로그인 성공·실패, 접속 IP와 포트, 사용한 인증 방식(비밀번호/키)과 키 지문, sudo 로 실행한 명령, su 전환, 계정 생성·비밀번호 변경, SFTP 파일 전송.',
    look:['"Failed password" 가 한 IP 에서 수십~수천 번 → 무차별 대입 공격','그 IP 의 "Accepted password" → 침입 성공 시각 (사고의 시작점)','"Accepted publickey" 의 키 지문이 처음 보는 것 → 공격자가 심어 둔 키','sudo COMMAND= 줄 → root 권한으로 무엇을 했는지','useradd / passwd → 백도어 계정'],
    limit:'연도가 안 적혀 있고(syslog 형식) 보통 1주 단위로 로테이션돼 auth.log.1, .2.gz … 로 넘어갑니다. 공격자가 root 면 줄 단위로 지울 수 있어 wtmp·audit 과 교차 확인이 필요합니다.',
    cmd:"grep -E 'Accepted|Failed' /var/log/auth.log | tail -50" },
  { k:'history', name:'셸 히스토리', files:'/root/.bash_history\n/home/계정/.bash_history (.zsh_history 등)', kind:'셸 히스토리', prio:1,
    what:'사용자가 셸에 직접 입력한 명령 원문. 파이프(|)·리다이렉트(>) 까지 그대로 남아 공격자가 무엇을 하려 했는지 가장 읽기 쉽습니다.',
    look:['wget/curl 로 받은 파일과 그 주소 → 악성코드 유포지','mysqldump, tar, scp, curl -T → 데이터 유출 흐름','useradd, authorized_keys, crontab → 백도어','history -c, unset HISTFILE → 흔적 삭제 시도 (그 뒤는 비어 있을 수 있음)'],
    limit:'기본 설정에서는 실행 시각이 없습니다(#1696… 같은 줄이 있으면 시각 있음). 로그아웃할 때 저장되므로 강제 종료되면 빠지고, 공격자가 쉽게 지우거나 끌 수 있어 "없다고 안 했다"는 뜻은 아닙니다.',
    cmd:'cat -n /root/.bash_history' },
  { k:'audit', name:'auditd (감사 로그)', files:'/var/log/audit/audit.log*', kind:'auditd', prio:1,
    what:'커널이 기록하는 실행 기록. 실행된 모든 프로그램(EXECVE)의 인자, 실행 계정, 로그인 세션 번호(ses), 작업 폴더까지 남습니다.',
    look:['히스토리에는 없는데 audit 에만 있는 명령 → 기록을 끈 뒤 실행한 명령','scp -f 파일 → 외부로 파일이 복사됨','auid(원래 로그인 계정)와 uid(실행 계정)가 다르면 sudo/su 로 권한을 바꾼 것','ses 번호로 어떤 SSH 접속에서 실행됐는지 연결'],
    limit:'auditd 가 설치·실행 중이고 execve 감시 규칙이 있어야 명령이 남습니다(기본은 로그인 정도만). 인자는 16진수로 인코딩되는 경우가 있어 그냥 읽기 어렵습니다(이 뷰어가 풀어서 보여 줌).',
    cmd:'ausearch -m EXECVE -i --start today' },
  { k:'wtmp', name:'로그인 기록 (wtmp / btmp)', files:'/var/log/wtmp (성공·로그아웃)\n/var/log/btmp (실패)', kind:'wtmp', prio:2,
    what:'터미널 로그인·로그아웃 시각과 접속 IP. btmp 에는 실패한 로그인과 시도한 계정 이름.',
    look:['auth.log 에는 없는데 wtmp 에만 있는 로그인 → auth.log 를 지운 흔적','로그인~로그아웃 시간으로 공격자가 얼마나 머물렀는지'],
    limit:'바이너리 파일이라 cat 으로 못 봅니다. SFTP·scp 처럼 터미널 없는 접속은 남지 않습니다.',
    cmd:'last -f /var/log/wtmp -i | head\nlastb -f /var/log/btmp -i | head' },
  { k:'mysql', name:'MySQL / MariaDB 로그', files:'/var/log/mysql/*.log (general log)', kind:'MySQL', prio:2,
    what:'general log 를 켜 두면 DB 에 들어온 모든 쿼리와 접속 계정·호스트가 남습니다.',
    look:['"SELECT /*!40001 SQL_NO_CACHE */ * FROM" 이 테이블마다 연속 → mysqldump 로 통째 덤프','INTO OUTFILE / LOAD_FILE → DB 를 통해 서버 파일을 쓰거나 읽음','평소와 다른 호스트·계정의 Connect'],
    limit:'general log 는 기본으로 꺼져 있어 대부분 서버에는 없습니다. 그럴 땐 셸 히스토리·auditd 의 mysqldump 명령이 유일한 단서입니다.',
    cmd:"grep -n 'SQL_NO_CACHE' /var/log/mysql/mysql.log | head" },
  { k:'pg', name:'PostgreSQL 로그', files:'/var/log/postgresql/*.log', kind:'PostgreSQL', prio:2,
    what:'접속 기록(log_connections), 실행한 SQL(log_statement), 인증 실패.',
    look:['application_name=pg_dump 접속 → DB 덤프','COPY … TO stdout 연속 → 테이블 데이터 추출','COPY … TO PROGRAM → DB 를 통해 OS 명령 실행'],
    limit:'접속·SQL 기록은 설정을 켜야 남습니다. 기본은 오류 위주라 덤프 흔적이 없을 수 있습니다.',
    cmd:"grep -n 'pg_dump\\|COPY' /var/log/postgresql/*.log" },
  { k:'ftp', name:'파일 전송 로그', files:'auth.log 의 internal-sftp 줄\n/var/log/xferlog, vsftpd.log', kind:'FTP', prio:2,
    what:'SFTP 로 열고 닫은 파일과 읽은/쓴 바이트 수, FTP 업로드·다운로드.',
    look:['"bytes read" 가 큰 파일 → 외부로 내려받아 간 파일과 크기','/tmp 아래 숨김 폴더의 압축 파일 → 미리 묶어 둔 유출 자료'],
    limit:'SFTP 파일 단위 기록은 sshd_config 에 "Subsystem sftp internal-sftp -l VERBOSE" 가 있어야 남습니다. scp 다운로드는 auditd 로만 보입니다.',
    cmd:"grep 'internal-sftp' /var/log/auth.log | grep -E 'open|close'" },
  { k:'etc', name:'계정·설정 파일', files:'/etc/passwd, ~/.ssh/authorized_keys,\ncrontab (/var/spool/cron, /etc/cron*)', kind:null, prio:3,
    what:'로그는 아니지만 공격자가 남긴 백도어가 그대로 있는 곳입니다.',
    look:['/etc/passwd 의 UID 0 계정 (root 말고 0 이 있으면 백도어)','authorized_keys 에 모르는 키','crontab 에 /tmp 나 숨김 폴더의 스크립트',
      'known_hosts → 이 서버에서 SSH 로 "나간" 적 있는 서버 목록 (측면 이동 대상 확인)'],
    limit:'이 뷰어는 /etc/passwd 와 known_hosts 만 읽습니다. authorized_keys·crontab 은 서버에서 직접 확인하세요. known_hosts 가 해시(|1|…)로 저장돼 있으면 주소를 바로 알 수 없습니다.',
    cmd:"awk -F: '$3==0' /etc/passwd\ncat /root/.ssh/authorized_keys\ncrontab -l; ls -la /etc/cron.*" },
];
function guideView(){
  const loaded = new Set(M.sources.map(x=>x.kind));
  const steps = `<div class="panel" style="margin-bottom:16px"><h2>어떤 순서로 보면 되나요?</h2>
    <ol class="gsteps">
      <li><b>언제, 어디로 들어왔나</b> — SSH·계정 로그에서 무차별 대입과 첫 로그인 성공(IP, 계정, 시각)을 찾습니다. → <a data-act="guidego" data-v="ips">공격자 IP</a></li>
      <li><b>들어와서 무엇을 했나</b> — 그 접속(세션) 동안 실행된 명령을 셸 히스토리·auditd 로 봅니다. → <a data-act="guidego" data-v="sessions">세션</a> · <a data-act="guidego" data-v="history">히스토리</a></li>
      <li><b>무엇을 가져갔나</b> — DB 덤프, 압축, 업로드·SFTP·scp 다운로드를 찾습니다. → <a data-act="kpi-go" data-v="3">DB 덤프</a> · <a data-act="kpi-go" data-v="4">파일 전송</a></li>
      <li><b>다시 들어올 문을 남겼나</b> — 계정 생성, SSH 키, crontab, 숨김 폴더의 실행 파일. → <a data-act="kpi-go" data-v="5">지속성·흔적삭제</a></li>
      <li><b>다른 서버로 넘어갔나</b> — 이 서버에서 밖으로 나간 ssh·scp·curl·nc. 들어온 접속(⬇)과 나간 접속(⬆)은 남는 로그가 다릅니다: 들어온 건 auth.log 의 "from IP", 나간 건 실행한 명령과 known_hosts. → <a data-act="guidego" data-v="ips">접속 방향</a> · <a data-act="guidego" data-v="files">파일 추적</a></li>
      <li><b>흔적을 지웠나</b> — history 삭제, 로그 비우기, auth.log 와 wtmp·audit 이 서로 안 맞는 곳.</li>
    </ol></div>`;
  return steps + `<div class="gcards">${GUIDE.map(g=>{
    const has = g.kind && loaded.has(g.kind);
    return `<div class="panel gcard">
      <div class="g-h"><h2 style="margin:0">${esc(g.name)}</h2>${g.prio===1?'<span class="badge red">핵심</span>':''}
        ${g.kind?`<span class="badge${has?' ok':''}">${has?'✓ 이번 분석에 포함':'이번 분석에 없음'}</span>`:''}</div>
      <pre class="g-files">${esc(g.files)}</pre>
      <div class="g-sec"><div class="g-t">무엇이 남나</div><div>${esc(g.what)}</div></div>
      <div class="g-sec"><div class="g-t">이렇게 보면 됩니다</div><ul>${g.look.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>
      <div class="g-sec"><div class="g-t">한계·주의</div><div style="color:var(--muted)">${esc(g.limit)}</div></div>
      <div class="g-sec"><div class="g-t">서버에서 직접 볼 때</div><pre class="raw">${esc(g.cmd)}</pre></div></div>`;
  }).join('')}</div>`;
}

/* ── 소스 ── */
function sources(){
  return `<div class="tablewrap"><table class="srcs" style="min-width:560px"><thead><tr><th>로그 파일</th><th>종류</th><th style="text-align:right">이벤트</th></tr></thead><tbody>
    ${M.sources.map(s=>`<tr><td class="mono">${esc(s.path)}</td><td>${esc(s.kind)}</td><td style="text-align:right;font-variant-numeric:tabular-nums">${s.events.toLocaleString()}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">읽은 로그가 없습니다.</td></tr>'}
  </tbody></table></div>
  ${M.notes.length?`<div class="notes" style="margin-top:16px">${M.notes.map(n=>`<div>${esc(n)}</div>`).join('')}</div>`:''}
  <p style="color:var(--muted);font-size:12.5px;margin-top:16px">분석 루트: <span class="mono">${esc(M.root)}</span> · 시간대 ${esc(M.tz_label)} · secviewer ${esc(M.version)}</p>`;
}

/* ── 렌더 / 이벤트 ── */
function render(){
  renderNav();
  const v = {overview, timeline, ips, sessions, sources, upload:uploadView, history:historyView, guide:guideView, files:filesView}[st.view];
  $('#main').innerHTML = v();
  if(st.view==='timeline'){
    const q = $('#q'); let t;
    q.oninput = ()=>{ clearTimeout(t); t=setTimeout(()=>{ st.q=q.value; st.limit=300; const pos=q.selectionStart; render(); const n=$('#q'); n.focus(); n.setSelectionRange(pos,pos); },160); };
    $('#sev').onchange = ev=>{ st.minSev=+ev.target.value; render(); };
    $('#scope').onchange = ev=>{ st.scope=ev.target.value; st.limit=300; render(); };
    $('#noise').onchange = ev=>{ st.hideNoise=ev.target.checked; render(); };
    $('#explain') && ($('#explain').onchange = ev=>{ st.explain=ev.target.checked; try{ localStorage.setItem('secview-explain', st.explain?'1':'0'); }catch(_){} render(); });
  }
  if(st.view==='ips'){
    const si = $('#srvip');
    if(si) si.onchange = ()=>{ try{ localStorage.setItem('secview-server-ip', si.value.trim()); }catch(_){} SERVER_IPS = si.value.split(/[\s,]+/).filter(Boolean); if(!si.value.trim()) loadServerIps(); render(); };
  }
  if(st.view==='files'){
    const q = $('#fq'); let t;
    if(q) q.oninput = ()=>{ clearTimeout(t); t=setTimeout(()=>{ fv.q=q.value; const pos=q.selectionStart; render(); const n=$('#fq'); n.focus(); n.setSelectionRange(pos,pos); },160); };
    const o = $('#fonly'); if(o) o.onchange = ev=>{ fv.only=ev.target.checked; render(); };
    if(fv.focus){ const i=(D.files||[]).findIndex(f=>f.path===fv.focus); const el=document.getElementById('file-'+i); if(el){ el.scrollIntoView({block:'center'}); } }
  }
  if(st.view==='history'){
    const q = $('#hq'); let t;
    if(q) q.oninput = ()=>{ clearTimeout(t); t=setTimeout(()=>{ hv.q=q.value; const pos=q.selectionStart; render(); const n=$('#hq'); n.focus(); n.setSelectionRange(pos,pos); },160); };
    const rk = $('#hrisky'); if(rk) rk.onchange = ev=>{ hv.risky=ev.target.checked; render(); };
    const hx = $('#hexplain'); if(hx) hx.onchange = ev=>{ st.explain=ev.target.checked; try{ localStorage.setItem('secview-explain', st.explain?'1':'0'); }catch(_){} render(); };
  }
}
function openEvent(i){
  const e = E[i];
  st.open = new Set([i]);
  const f = {cats:new Set(Object.keys(CATS)), minSev:0, q:'', ip:null, user:null, sid:e.sid||null, hideNoise:!isNoise(e)};
  if(!e.sid){ f.ip = e.ip||null; }
  const rows = (Object.assign(st,f), filtered());
  st.limit = Math.max(300, rows.indexOf(e)+50);
  st.view='timeline'; render();
  const el = document.querySelector(`tr.ev[data-v="${i}"]`); if(el) el.scrollIntoView({block:'center'});
}
document.addEventListener('click', ev=>{
  const t = ev.target.closest('[data-act]'); if(!t) return;
  const a = t.dataset.act, v = t.dataset.v;
  if(a!=='row') ev.stopPropagation();
  switch(a){
    case 'view': go(v, v==='timeline'?{}:{ip:null,sid:null}); break;
    case 'kpi': window._kpi[+v](); break;
    case 'kpi-go': overview(); window._kpi[+v](); break;
    case 'kpi-high': go('timeline',{minSev:3,cats:new Set(Object.keys(CATS)),ip:null,user:null,sid:null,q:''}); break;
    case 'cat': st.cats.has(v)?st.cats.delete(v):st.cats.add(v); st.limit=300; render(); break;
    case 'allcats': st.cats = st.cats.size===Object.keys(CATS).length?new Set():new Set(Object.keys(CATS)); render(); break;
    case 'ip': go('timeline',{ip:v,sid:null,dest:null,fpath:null,scope:'all',cats:new Set(Object.keys(CATS))}); break;
    case 'user': go('timeline',{user:v}); break;
    case 'clr': st[v]=null; render(); break;
    case 'clrrange': st.range=null; st.rangeLabel=null; render(); break;
    case 'binunit': ch.bin=v; try{ localStorage.setItem('secview-bin', v); }catch(_){} render(); break;
    case 'chartshow': ch.show=!ch.show; try{ localStorage.setItem('secview-chart', ch.show?'1':'0'); }catch(_){} render(); break;
    case 'bin': {
      const C = CHARTS[t.dataset.c]; if(!C) break;
      const b = C.bins[+t.dataset.i], lab = binLabel(b, C.unit) + (C.unit==='hour' ? ' ~ '+iso(b.end).slice(11,13)+'시' : '');
      TIP.style.display = 'none';
      const f = {range:[b.start, b.end], rangeLabel:lab, limit:300};
      if(t.dataset.c.startsWith('sm-')) Object.assign(f, {cats:new Set([C.mode]), minSev:0});
      if(st.view==='timeline'){ Object.assign(st, f); render(); }
      else go('timeline', Object.assign(f, {ip:null, user:null, sid:null, dest:null, fpath:null, scope:'all', q:'', ...(t.dataset.c.startsWith('sm-')?{}:{cats:new Set(Object.keys(CATS)), minSev:0})}));
      break;
    }
    case 'more': st.limit+=500; render(); break;
    case 'csv': csv(); break;
    case 'row': { const i=+v; st.open.has(i)?st.open.delete(i):st.open.add(i); const y=window.scrollY; render(); window.scrollTo(0,y); break; }
    case 'ev': openEvent(+v); break;
    case 'sess': go('sessions',{sid:v,ip:null}); setTimeout(()=>{ const el=document.getElementById('sess-'+v); if(el){ el.open=true; el.scrollIntoView({block:'start'}); window.scrollBy(0,-110);} },0); break;
    case 'ipsess': go('sessions',{ip:v}); break;
    case 'ipcard': go('ips'); setTimeout(()=>{ const el=document.getElementById('ip-'+v); if(el){ el.scrollIntoView({block:'center'}); el.style.outline='2px solid var(--accent)'; } },0); break;
    case 'pick': $('#fin').click(); break;
    case 'dest': go('timeline',{dest:v,ip:null,sid:null,user:null,fpath:null,scope:'all',cats:new Set(Object.keys(CATS)),minSev:0,q:''}); break;
    case 'destcard': go('ips'); setTimeout(()=>{ const el=document.getElementById('dest-'+v); if(el){ el.scrollIntoView({block:'center'}); el.style.outline='2px solid var(--accent)'; } },0); break;
    case 'file': fv.focus=v; fv.q=''; fv.only=false; go('files'); break;
    case 'fpath': go('timeline',{fpath:v,ip:null,sid:null,user:null,dest:null,scope:'all',cats:new Set(Object.keys(CATS)),minSev:0,q:''}); break;
    case 'hfile': hv.file=+v; hv.q=''; render(); window.scrollTo(0,0); break;
    case 'hline': { const e = E[+v]; if(e) openEvent(+v); break; }
    case 'guidego': go(v); break;
    case 'pickdir': $('#din').click(); break;
  }
});
renderMeta();
render();
checkServer();
})();
</script>
</body>
</html>
'''

if __name__ == '__main__':
    main()
