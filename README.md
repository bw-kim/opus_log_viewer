# secviewer — 리눅스 침해사고 로그 뷰어

**SSH로 들어와서 → 무슨 명령을 쳤고 → DB를 덤프하고 → 파일을 빼갔는지**를 여러 로그에서 모아
한 화면(단일 HTML)으로 보여주는 도구입니다. Python 3.8+ 표준 라이브러리만 사용하므로
**서버에 `secviewer.py` 파일 하나만 올려서** 바로 실행할 수 있습니다.

## 사용법

### 방법 A — 웹 화면에 로그를 끌어다 놓기 (가장 쉬움)

```bash
python secviewer.py --web          # Windows 에서는 인자 없이 python secviewer.py 만 해도 됨
```

브라우저가 `http://127.0.0.1:8080` 으로 열리면 **로그 불러오기** 탭(첫 화면)에
로그 파일 / 폴더 / 압축파일(`zip`, `tar.gz`)을 끌어다 놓으면 바로 분석됩니다.

- 서버에서 증거를 한 번에 모으는 명령:
  `sudo tar czf evidence.tgz /var/log /root/.*_history /home/*/.*_history /etc/passwd`
  → 이 `evidence.tgz` 를 그대로 끌어다 놓으면 됩니다.
- 파일 이름이 바뀌어 있어도(`messages`, `syslog`, `log1.txt` …) 내용을 보고 SSH / audit / MySQL / PostgreSQL / FTP / wtmp 로그를 자동 인식합니다.
- 결과를 보는 중에 **새 로그를 또 끌어다 놓으면 지금 결과에 합쳐서** 다시 분석합니다(어느 탭에서든 가능).
  같은 내용의 파일은 자동으로 건너뜁니다. 처음부터 새로 하려면 업로드 화면에서 "지금 결과에 추가로 합치기"를 끄세요.
- syslog 처럼 시간대가 안 적힌 로그는 화면의 **로그 시간대**(서버 시간대)를 맞춰 주세요.
- 저장된 리포트 HTML 파일(`samples_report.html` 등)을 그냥 열었을 때는 업로드가 동작하지 않습니다(분석 서버가 없음). `--web` 으로 띄운 화면을 쓰세요.

### 방법 B — 서버에서 직접 분석

```bash
# 1) 침해 서버에서 직접 분석 (root 권한 권장)
sudo python3 secviewer.py                      # → secview_report.html

# 2) 분석 후 바로 브라우저로 보기 (127.0.0.1 에만 바인드)
sudo python3 secviewer.py --serve 8080
ssh -L 8080:127.0.0.1:8080 user@server         # 내 PC 에서 터널 후 http://127.0.0.1:8080

# 3) 증거를 수집해 와서 오프라인 분석 (/ 구조 그대로 복사한 폴더)
python3 secviewer.py --root ./evidence --tz +09:00 -o report.html --json report.json
```

증거 수집 예시:

```bash
sudo tar czf evidence.tgz /var/log /root/.*_history /home/*/.*_history /etc/passwd
```

주요 옵션: `--tz +09:00`(syslog 시간대), `--year 2026`(연도 없는 syslog), `--since 2026-10-01`,
`--audit-all`(데몬 명령까지 포함), `--no-journal`.

## 무엇을 읽고, 무엇을 잡는가

| 분류 | 로그 소스 | 탐지 내용 |
|---|---|---|
| SSH 인증 | `auth.log*`, `secure*` (없으면 `journalctl`), `btmp`, audit `USER_LOGIN` | 로그인 실패/성공, **무차별 대입 후 성공**, 백도어 계정 로그인, 사용된 키 지문 |
| 세션 | sshd pid, `wtmp`, audit `ses=` | 로그인~로그아웃 구간을 묶고, 그 안에서 실행된 명령/전송/덤프를 연결 |
| 명령어 | `~/.bash_history`(타임스탬프 지원), `.zsh_history`, auditd `EXECVE`, sudo `COMMAND=` | 히스토리 ↔ auditd 자동 병합(파이프라인 원문 + 세션/IP) |
| DB 덤프 | 명령어, MySQL general log, PostgreSQL 로그, `.mysql_history` | `mysqldump`/`pg_dump`/`mongodump`/`redis --rdb`, `SQL_NO_CACHE` 패턴, `pg_dump` 접속, `COPY TO`, `INTO OUTFILE`, DB 파일 직접 복사 |
| 웹 접속 | nginx·apache `access.log` (combined/common, vhost 형식, 줄 끝 X-Forwarded-For) | 요청량·IP·상태 코드, 웹셸 의심 경로, SQL 인젝션·명령 실행·경로 조작·Log4Shell 시도, 404 대량 스캔, 스캐너 UA, 로그인 무차별 대입, 업로드, 대용량 백업 다운로드 |
| 파일 전송 | 명령어, SFTP(`internal-sftp`), vsftpd/xferlog | 방향 구분 — **scp -f / SFTP read / curl -T / scp·rsync host: = 유출**, wget·curl = 반입 |
| 지속성 | 명령어, `useradd`/`chpasswd` 로그, `/etc/passwd` | UID 0 계정, authorized_keys, crontab, systemd, rc.local |
| 흔적 삭제 | 명령어, 로그 간 교차검증 | `history -c`, `unset HISTFILE`, 로그 삭제 — wtmp/audit 에는 있는데 auth.log 에 없는 로그인 |
| 기타 | 명령어 | 리버스 셸, 악성 실행(/tmp 실행, nohup, base64 -d), 자격증명 탐색, 정찰 |

> SFTP 파일 단위 기록은 `sshd_config` 에 `Subsystem sftp internal-sftp -l VERBOSE` 설정이 있어야 남습니다.
> scp 원격 다운로드(`scp -f`)는 auditd 가 켜져 있어야 보입니다.

## 뷰어 화면

- **개요**: 핵심 지표(침입 IP, 로그인 실패, 명령, DB 덤프, 파일 전송, 지속성) + 시간순 공격 흐름
- **기간 필터**: 모든 화면 위의 "기간 [시작] ~ [끝]" 으로 개요·타임라인·접속 방향·세션·파일 추적·히스토리를 한꺼번에 좁힘
  (마지막 1일/7일/30일 버튼, 막대그래프 클릭도 같은 필터). 로그가 아주 많으면 웹 모드에서 **이 기간만 다시 분석**,
  업로드 화면의 "분석 기간", 또는 `--since 2026-10-01 --until 2026-10-05` 로 처음부터 기간을 잘라 분석
- **날짜별 막대그래프**: 개요에 전체(위험도 높음 이상 강조) + 분류별 작은 막대 그래프, 타임라인 위에는 현재 필터 기준 그래프.
  기간이 3일 이하면 시간별, 길면 일별(직접 전환 가능). 막대에 마우스를 올리면 내역, 누르면 그 기간만 타임라인으로
- **타임라인**: 분류/위험도/검색/IP·계정·세션 필터, 행 클릭 시 원본 로그·출처 파일:줄, CSV 내보내기
- **명령어 해설**: 명령마다 "무엇을 했는지 / 이 사고에서 어떤 의미인지 / 무엇을 확인할지"를 문장으로 풀어서 표시
  (예: `scp -f 파일` → "외부에서 이 서버의 파일을 scp 로 가져갔습니다(유출)…"). 타임라인의 **명령어 해설 보기**로 켜고 끔
- **접속 방향**: ⬇ 들어온 접속(다른 곳 → 이 서버, auth.log 의 `from IP`)과 ⬆ 나간 접속(이 서버 → 다른 곳, 실행한
  ssh·scp·curl·wget·nc 명령과 `known_hosts`)을 나눠서 표시. 서버 IP 를 입력하면(또는 `--server-ip`, 로그에서 자동 감지)
  서버 자신에서 출발한 로그인을 구분하고, 직전에 `ssh` 를 실행한 세션을 "실제 출발지"로 연결
- **웹 접속**: access log 요약 — 시간별 요청량(의심 요청 강조), 웹셸 의심 경로, 의심 요청 목록(유형별 필터), 접속 IP 순위
  (SSH 로도 들어온 IP 표시), 큰 응답, 많이 요청된 경로, **전체 요청 검색**(IP·주소·상태·UA; 5만 건이 넘으면 의심 IP 의 요청만 보관)
- **파일 추적**: 파일마다 저장 → 압축 → 이동·복사 → 외부 유출(scp·SFTP·curl·rsync·nc) → 삭제 이력을 시간순으로
- **세션**: `root@45.133.1.77` 같은 로그인 단위로 그 세션에서 한 일을 순서대로
- **히스토리**: `.bash_history` 등 원문을 줄 번호와 함께 열람. 줄마다 위험도·해설, 실행 시각(있을 때), 기록 삭제 명령 이후 구간 경고
- **로그 소스**: 읽은 파일과 경고(권한 부족, wtmp 변조 의심 등)
- **로그 가이드**: 봐야 할 로그별로 무엇이 남는지, 어떻게 보면 되는지, 한계, 서버에서 직접 보는 명령 + 조사 순서
  - **명령어 모음**: 침해사고 조사용 리눅스 명령 66개를 8개 분류(로그 검색 기본, SSH·로그인, 실행한 명령, 파일·시간 추적,
    계정·백도어, 프로세스·네트워크, 웹 접근 로그, 증거 보존)로 정리 — 명령마다 용도·옵션 설명, 검색, 복사 버튼
- **로그 불러오기**: 파일·폴더·압축파일 드래그 앤 드롭 업로드, 파일별 인식 결과 표시

## 데모

```bash
python make_sample.py                                   # samples/ 에 가상 침해 시나리오 생성
python secviewer.py --root samples --tz +09:00 -o samples_report.html
```

시나리오: 무차별 대입 → root 로그인 → wp-config 열람 → mysqldump/pg_dump → curl 업로드 유출 →
악성 스크립트 실행 → UID 0 백도어·SSH 키·crontab → history 삭제 → SFTP/scp 로 추가 유출 → 백도어 계정 재접속.

## 주의

- `--web`/`--serve` 는 기본으로 `127.0.0.1` 에만 열립니다. `--bind 0.0.0.0` 으로 열면 같은 망의 누구나 로그를 올리고 결과를 볼 수 있습니다.
- 리포트에는 명령 원문(비밀번호가 포함될 수 있음)과 원본 로그가 그대로 들어갑니다. 공유에 주의하세요.
- `ip_inferred`(기울임체 IP)는 로그에 직접 찍힌 값이 아니라 같은 시간대 유일한 외부 세션으로 추정한 값입니다.
- 규칙 기반 탐지이므로 누락/오탐이 있을 수 있습니다. 판단은 원본 로그(행 클릭)로 확인하세요.
