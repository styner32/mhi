# Mobile HTTP Inspector — Go CLI 구현 명세서 v0.3

- 작성일: 2026-10-30 (KST)
- 사용자 결정: Go CLI, 도메인 모니터링 후 선택적 SSL Proxying, YAML/`.env` 설정, 로컬 생성 CA만 사용, 공개 CA는 사용자가 AirDrop으로 전달한다.
- 상태: 구현 전 명세. 아래 CLI, 타입, 출력은 제안 계약이며 구현된 프로그램이 아니다.
- 우선 대상: macOS Apple Silicon + 실제 iPhone + 신뢰 가능한 동일 LAN
- 가칭 실행 파일: `mhi` (Mobile HTTP Inspector)
- 목적: 본인 또는 명시적으로 허가받은 앱의 HTTP/HTTPS 요청을 로컬에서 관찰한다.
- 대체 문서: `mobile-http-inspector-go-cli-spec-v0.2.md`를 전면 대체한다. 이 문서가 단독 구현 기준이다. 실제 구현·실기기 테스트·인증서 생성은 아직 수행하지 않았다.

## 0. 결정 요약과 v0.2 대비 변경

**처음에는 HTTPS를 복호화하지 않고 CONNECT 목적지만 모니터링한다. 사용자가 설정에 추가한 정확한 호스트에 대해서만, 새 연결부터 로컬 CA를 이용한 SSL Proxying을 수행한다.**

| 영역 | v0.2 | v0.3 |
|---|---|---|
| 빈 대상 목록 | 시작 거부 | 정상 모니터링 상태. 모든 승인된 비대상 HTTPS는 터널링 |
| 관찰 범위 | 허용 호스트의 HTTP flow 중심 | 승인 기기의 CONNECT 목적지 메타데이터 + 선택 호스트의 정제 HTTP flow |
| SSL Proxying | 시작 인자에 고정 | `ssl_proxy.enabled` + `ssl_proxy.domains`를 설정 파일로 관리 |
| 구성 | CLI 중심, YAML은 후속 | YAML + `.env` + 프로세스 환경변수 + 명시적 CLI |
| 실행 중 변경 | 후속 | `--watch` 또는 SIGHUP으로 정책 재읽기. 새 CONNECT부터 적용 |
| CA 출처 | 독립 생성 CA | `mhi ca init`으로 로컬 생성한 앱 소유 CA만 사용. 외부 CA import 없음 |
| CA 전달 | export 명령·임시 다운로드 handler | init 시 공개 DER `.cer`도 생성. `ca path`로 경로만 출력. 사용자가 AirDrop |
| 설치 기능 | `--install-ca` | 제거. 다운로드 서버·QR·프로파일 배포·키체인 설치 없음 |
| 그대로 유지 | Go 단일 바이너리, 조회 전용 | Mac 키체인/시스템 프록시 미변경, 정제 JSON, bounded streaming, 안전한 종료 |

GoProxy는 CONNECT 처리 시 터널 또는 MITM을 선택할 수 있다. 설정의 원자적 교체와 연결별 정책 스냅샷은 이 제품에서 구현한다. 라이브러리가 자동으로 hot reload나 이 문서의 안전 정책을 제공한다고 가정하지 않는다. [S1][S2][S7]

## 1. 성공 기준과 지원 범위

### 1.1 첫 번째 성공 시나리오

1. `mhi ca init`으로 CA를 생성하고 `mhi ca path`가 출력한 공개 `.cer` 파일을 사용자가 AirDrop한다.
2. 사용자가 iPhone에 인증서를 설치·신뢰하고 Wi-Fi 프록시를 설정한다. 이 앱은 설치를 수행하지 않는다.
3. `ssl_proxy.enabled: false`, `domains: []`로 `mhi serve --config ./mhi.yml --watch`를 실행한다.
4. 목적지 호스트·포트와 연결 발생 시각을 보고 필요한 API를 찾는다. 이 단계에서 HTTPS 내부 URL·헤더·본문은 보이지 않는다.
5. 파일에서 `ssl_proxy.enabled: true`와 특정 `domains`를 저장한다. 유효한 정책만 원자적으로 반영한다.
6. 해당 앱에서 새 연결을 만들면 그 호스트만 MITM된다. 기존 터널은 자동 전환되지 않으며 별도로 재연결이 필요할 수 있다.
7. Ctrl+C로 소유 연결을 닫는다. 프록시 종료, CA 로컬 삭제, iPhone 신뢰 해제는 별개다.

순수 모니터링은 CA가 없어도 시작할 수 있다. 다만 실행 중 CA 생성/교체는 P0에서 허용하지 않는다. 같은 실행에서 MITM을 켤 계획이면 시작 전에 CA를 생성해 둔다.

### 1.2 범위

| 우선순위 | 기능 |
|---|---|
| P0 | Go CLI, HTTP/1.1 explicit proxy, CONNECT 목적지 모니터링, 선택 호스트 MITM, YAML/`.env` 설정, 정책 reload, 로컬 CA 생성·상태·공개 파일 경로·삭제, 승인 IP와 proxy auth, 정제 메타데이터/JSON, text/JSONL, 명시적 파일 저장, 종료 |
| P1 | 검증된 HTTP/2 MITM, TUI, 오프라인 inspect, wildcard, 도메인 집계 화면, 사용자 승인하의 특정 연결 재접속, 폼 정제, HAR, WebSocket/SSE 메시지 분석 |
| 제외 | CA import·외부 CA 다운로드·공유 CA 사용, CA 다운로드 endpoint/설치 기능/QR, GUI, 별도 관리 서버, 데몬, Pinning 우회, 요청 변조·재전송, 클라우드 전송, 시스템 키체인 변경 |

P0의 MITM 구간은 HTTP/1.1로 검증한다. passthrough 터널 내부에서 클라이언트와 서버가 HTTP/2 등을 협상해도 이를 파싱하거나 HTTP/2 분석 지원이라고 표시하지 않는다. SSE는 본문을 저장하지 않고 전달한다. WebSocket Upgrade 전달은 실제 검증 범위만 지원으로 표시한다.

### 1.3 구조적으로 남는 한계

프록시 경로를 사용하지 않는 요청은 보이지 않는다. 루트 CA 신뢰만으로 앱의 Pinning이나 별도 신뢰 정책을 무력화할 수 없다. IP로 요청 앱의 이름을 확정하지 않는다. TLS 중계와 프로토콜 협상은 원래 연결의 타이밍·동작에 영향을 줄 수 있다. 이 도구는 패킷 원본을 완전히 보존하는 캡처 도구가 아니다.

## 2. 기술 선택

| 영역 | 선택 |
|---|---|
| 언어 | Go. 구현 시작 시 지원 중인 안정 버전을 선택하고 CI/toolchain에 고정 |
| CLI | `github.com/spf13/cobra`; Viper는 P0에 추가하지 않음 |
| 프록시 | `github.com/elazarl/goproxy`, 소스 확인 기준 `v1.9.2`; M0 통과 후 의존성 고정 |
| 인증서/키 | `crypto/rand`, `crypto/ecdsa`, `crypto/x509`, `crypto/tls`, `encoding/pem` |
| 이벤트/설정 | `encoding/json`, 명시적 Go 타입; YAML decoder와 `.env` parser는 아래 정책 적용 |
| 설정 도구 | `go.yaml.in/yaml/v3` strict decoding, `joho/godotenv`의 map 파싱, `fsnotify` 디렉터리 watch |
| 동시성 | `context`, goroutine, bounded channel, mutex/atomic |
| 진단 | `log/slog` 또는 제한된 구조화 logger. 원시 프록시 로그를 그대로 출력하지 않음 |
| 테스트 | `testing`, `httptest`, TLS fixture, `go test -race`, fuzzing |
| 배포 | macOS arm64 실행 파일. Python/Node/mitmdump 실행 의존성 없음 |

GoProxy의 CONNECT 분기와 사용자 지정 TLSConfig를 사용한다. P0의 MITM 연결은 HTTP/1.1로 제한하고 실제 협상 결과를 검증한다. passthrough에서는 TLS 협상에 개입하지 않는다. 의존성 버전은 구현 시 검증해 go.mod/go.sum에 고정하며, 문서에 언급한 버전이 최신이라고 주장하지 않는다. [S2]

### 2.1 반드시 덮어써야 할 라이브러리 기본값

확인한 GoProxy v1.9.2에는 내장 CA/개인키가 있고, 기본 transport는 서버 인증서 검증 생략과 환경 프록시 사용을 포함한다. 샘플 코드를 제품 기본값으로 사용하지 않는다. [S3][S4]

- 사용자별 독립 CA를 명시적으로 주입한다. `AlwaysMitm`/기본 `MitmConnect`의 내장 CA에 의존하지 않는다.
- upstream TLS 검증을 켠 자체 `http.Transport`를 제공한다. `InsecureSkipVerify`는 false이며 P0에 `--insecure` 옵션을 두지 않는다.
- 일반 HTTP 및 CONNECT dial 경로 모두 환경 프록시를 자동 사용하지 않는다. `HTTP_PROXY`/`HTTPS_PROXY`로 자기 자신에게 재귀 연결하지 않는다.
- 원본 Accept-Encoding을 유지하고 자동 압축 요청/자동 해제를 비활성화한다. 본문 분석용 압축 해제는 관찰 사본에만 적용한다.
- 라이브러리 verbose/raw error logging을 차단하고 정제된 진단 코드만 노출한다.
- `Proxy-Authorization`은 실제 서버로 전달하지 않는다. 앱의 `Authorization`과 구별한다.

## 3. 아키텍처

```text
iPhone 앱 / Safari
    │ Wi-Fi HTTP proxy + 프록시 인증
    ▼
선택한 Mac LAN IP:9090
┌────────────────── Go process: mhi ─────────────────────┐
│ Client gate → 목적지 정책 → 연결별 SSL 정책 snapshot   │
│                               │                        │
│                               ├── 원래 서버로 전달     │
│                               │                        │
│                        bounded observation             │
│                               ↓                        │
│                        sanitize / classify             │
│                               ↓                        │
│                        bounded event queue             │
│                               ↓                        │
│                    text / JSONL / optional file        │
└────────────────────────────────────────────────────────┘
```

네트워크 전달 경로에서 stdout·디스크 write 완료를 기다리지 않는다. 대기열이 차면 관찰 데이터를 생략하고 손실을 보고한다. GoProxy 타입은 `internal/proxy`에 가두며 CA/정제/출력 계층에 노출하지 않는다.

별도 HTTP 관리 서버, 브라우저 UI, WebSocket, IPC, REST API, 공개 CA 다운로드 handler를 만들지 않는다. 로컬 설정 watcher가 검증된 불변 정책을 교체하고, CONNECT handler가 연결마다 정책을 한 번 읽는다. 승인 기기에서 관찰한 비대상 CONNECT 호스트는 메타데이터로만 출력하며 raw tunnel 바이트를 저장하지 않는다.

## 4. CLI와 설정 계약

### 4.1 명령

| 명령 | 동작 |
|---|---|
| `mhi ca init` | 로컬에서 독립 CA key/cert와 공개 DER `.cer`를 함께 생성. 기존 파일 덮어쓰기 없음 |
| `mhi ca path` | AirDrop 가능한 공개 `.cer`의 절대 경로 한 줄만 stdout으로 출력 |
| `mhi ca status [--json]` | 지문·유효기간·파일 상태·키/인증서 일치·로컬 생성 기록 확인 |
| `mhi ca delete` | 사용 중이 아닐 때 지문 확인 후 앱 소유 CA 파일 삭제 |
| `mhi serve [--config PATH] [--env-file PATH] [--watch]` | 포그라운드 프록시·모니터링. Ctrl+C 종료 |
| `mhi config check ...` | 설정 문법·스키마·도메인·필요한 CA의 로컬 상태 검사. 리스너/신뢰 설치 없음 |
| `mhi config show ...` | 정제된 유효 설정과 필드별 출처 출력. 실행 중 프로세스의 상태 조회 기능은 아님 |
| `mhi doctor [--json]` | 로컬 파일·네트워크 후보만 읽기 전용 점검 |
| `mhi version` | 앱/Go/프록시 버전·build commit |

`ca export`와 `--install-ca`는 제거한다. 공개 `.cer`를 init에서 생성하므로 내보내기 단계가 필요 없다. `ca path`는 파일이 없으면 nonzero로 종료하며 CA를 자동 생성하지 않는다.

공통 옵션은 `--state-dir`, `--config`, `--env-file`, `--help`, `--no-color`. 파일은 명시적으로 지정한 것만 읽는다. CWD의 `.env`/YAML, 상위 디렉터리, 홈 파일을 자동 탐색하지 않는다. `--watch`는 serve 전용이고 명시한 config/env 파일이 하나 이상 필요하다.

### 4.2 구성 예시: 기본 모니터링

`mhi.yml`:

```yml
schema_version: 1
listen: "192.168.0.10:9090"
client: "192.168.0.25"

ssl_proxy:
  enabled: false
  domains: []

http_capture:
  domains: []

capture:
  body: none
  details: false

output:
  format: text
  file: ""
  max_bytes: 104857600
```

IP는 예시다. `ssl_proxy` 목록은 복호화 목록이지 목적지 접근 허용 목록이 아니다. 승인된 기기의 비대상 공개 HTTPS는 여전히 터널링한다. `http_capture.domains`는 평문 HTTP 관찰 대상이고 SSL 설정과 독립이다.

다음 부분만 변경하면 선택 호스트의 SSL Proxying을 켤 수 있다.

```yaml
ssl_proxy:
  enabled: true
  domains:
    - api.example.com
    - upload.example.com:443
```

첫 버전은 정확한 호스트만 지원한다. 포트 생략 시 443이다. `example.com`은 `api.example.com`을 포함하지 않는다. 전체 `*`, wildcard, 정규식, URL scheme/path는 거부한다. monitoring으로 돌아가려면 `enabled: false`로 바꾼다. 목록은 남겨도 되며 기존 연결의 처리 방식은 4.6을 따른다.

### 4.3 `.env` 방식

```dotenv
MHI_LISTEN=192.168.0.10:9090
MHI_CLIENT=192.168.0.25
MHI_SSL_PROXY_ENABLED=false
MHI_SSL_PROXY_DOMAINS=
MHI_HTTP_CAPTURE_DOMAINS=
MHI_BODY=none
MHI_DETAILS=false
MHI_FORMAT=text
MHI_OUTPUT=
MHI_MAX_OUTPUT_BYTES=104857600
```

복호화를 켜는 변경:

```dotenv
MHI_SSL_PROXY_ENABLED=true
MHI_SSL_PROXY_DOMAINS=api.example.com,upload.example.com:443
```

쉼표로 나누고 각 원소 양끝 공백을 제거한다. 전체 빈 값은 빈 배열을 명시하는 유효한 값이다. 쉼표 사이 빈 원소·중복 key·잘못된 bool·unknown `MHI_` key는 거부한다. list는 합치지 않고 우선순위가 높은 값 전체로 교체한다. 변수 미지정과 `MHI_SSL_PROXY_DOMAINS=`를 구별한다.

추가 매핑은 `MHI_STATE_DIR`, `MHI_REDACT_RULES`, `MHI_PROXY_PASSWORD_FILE`이다. 비밀번호/개인키 원문은 `.env` 설정 항목으로 받지 않는다. `.env`는 shell로 실행하지 않는다. MVP 형식은 literal `KEY=VALUE`, 선택적 인용부호와 주석만 지원한다. `$VAR`, `${VAR}`, `$(...)`, backtick, multiline, YAML식 `KEY: value` 확장은 지원하지 않는다. parser 앞단에서 subset 문법과 duplicate key를 검사한다.

### 4.4 우선순위와 검증

```text
명시적으로 지정한 CLI flag
  > 시작 시 스냅샷한 프로세스 환경변수 MHI_*
  > 명시한 .env 파일
  > 명시한 YAML 파일
  > 제품 기본값
```

CLI 기본값은 사용자가 지정한 값으로 취급하지 않는다. `false`, `""`, `[]`도 명시 값이다. hot reload 때 `.env`를 새 map으로 파싱하고 프로세스 환경변수에 주입하지 않는다. `godotenv.Load`를 반복 호출해 예전 값이 남는 구현을 피한다. Read/Parse 계열은 map 반환을 지원한다. [S8]

YAML은 unknown field, duplicate key, 추가 document, null 타입 혼동을 거부한다. 별칭/merge key/사용자 태그는 P0에서 허용하지 않는다. 파일 크기 64 KiB, 도메인 항목 수 128개 상한. `KnownFields(true)`만으로 모든 검증이 해결됐다고 가정하지 않는다. [S9]

상대 파일 경로는 해당 값을 정의한 파일의 디렉터리 기준으로 해석한다. CLI·프로세스 환경변수 경로는 시작 CWD 기준이다. `~/`는 경로 값에 한해 사용자 홈으로 확장한다. 일반 shell expansion은 없다. config/env/state/output 파일을 서로 같은 파일로 지정하지 못하게 한다.

`config show`는 각 필드의 출처를 표시한다. hot reload에서 파일 값을 바꿔도 CLI/env가 덮어쓰는 경우 `config.shadowed` 경고와 승리한 출처를 출력한다. 비밀값·원문 파일·환경변수 전체를 출력하지 않는다. 다른 터미널의 `export`가 이미 실행 중인 프로세스 값을 바꾼다고 설명하지 않는다.

시작 조건:

| enabled | domains | 결과 |
|---|---|---|
| false | 빈 목록 | 정상 모니터링. CA 불필요 |
| false | 유효한 목록 | 정상 모니터링. 목록은 비활성 상태로 보관 |
| true | 비어 있음 | 잘못된 설정. 시작/재적용 거부 |
| true | 유효한 목록 + 로컬 CA 준비 | 선택 호스트만 새 연결에서 MITM |
| true | CA 없음/불량/만료 | 거부. 내장 CA fallback·자동 생성·전체 MITM 없음 |

비활성 목록에도 잘못된 hostname이 있으면 오류다. 유효하지 않은 설정을 조용히 무시하지 않는다. reload 실패 시 마지막 정상 정책을 유지하고 유지 중인 revision과 SSL 상태를 명확하게 출력한다.

### 4.5 옵션 매핑과 재시작 경계

| 옵션 | 기본/의미 |
|---|---|
| `--listen` / `listen` | `127.0.0.1:9090`. iPhone에는 특정 LAN IPv4 명시. 전체 인터페이스 bind 거부 |
| `--client` / `client` | LAN bind 필수, TCP peer IP로 검증 |
| `--ssl-proxy` | `ssl_proxy.enabled`, 기본 false |
| `--mitm-host` | 반복 가능; `ssl_proxy.domains` 목록 전체 교체. 이 flag만으로 enabled를 true로 만들지 않음 |
| `--http-host` | `http_capture.domains`, 기본 [] |
| `--body` | `capture.body`, none 또는 json, 기본 none |
| `--details` | 정제 상세 출력, 기본 false |
| `--format` | `output.format`, text 또는 jsonl |
| `--output` | `output.file`, 비었으면 파일 저장 없음 |
| `--max-output-bytes` | `output.max_bytes`, 기본 100 MiB |
| `--redact-rules` | `redact_rules` JSON 파일 경로 |
| `--proxy-password-file` | `proxy_password_file`, 0600 파일. 원문 비밀번호 argv 금지 |

운영 중 hot reload되는 값은 `ssl_proxy.enabled`와 `ssl_proxy.domains`뿐이다. listen/client/state-dir/인증/capture/output/정제 규칙의 변경은 재시작이 필요하다. 재시작 필드가 바뀐 후보는 부분 적용하지 않고 전체 reject한다. 같은 경로의 정제 규칙/비밀번호/CA 파일을 자동 감시·교체하지 않는다.

프록시 username은 mhi. 비밀번호는 시작 시 128비트 이상 난수 생성해 `/dev/tty`에만 표시하거나 0600 파일에서 읽는다. non-TTY는 password file 필수다. 정상 정책 reload는 비밀번호를 바꾸지 않는다. Basic proxy 인증은 LAN 암호화가 아니므로 신뢰할 수 있는 네트워크를 전제로 한다.

### 4.6 실행 중 반영과 기존 연결

`--watch`는 명시한 config/env의 **부모 디렉터리**를 감시하고 대상 파일명만 필터링한다. 에디터가 임시 파일을 rename하여 저장하는 방식에도 동작해야 한다. fsnotify는 이런 이유로 파일 하나보다 디렉터리 watch를 권장한다. [S10]

watch는 300 ms debounce 후 전체 후보를 다시 읽고 검증한다. 파일 부재·편집 도중 문법 오류·권한 오류에서는 last-known-good를 유지한다. 같은 유효 설정은 revision을 올리지 않는다. watch error/overflow 시 즉시 전체 재검증하고 경고한다. 복구하지 못하면 watch가 멈췄다고 알리고 SIGHUP/재시작 경로를 안내한다. watcher와 SIGHUP reload는 하나의 직렬 coordinator를 사용한다.

SIGHUP은 `--watch` 없이도 명시한 파일을 다시 읽는다. PID는 시작 시 stderr로 출력한다. 예: `kill -HUP <시작 로그의 실제 PID>`. `pkill`로 다른 프록시 인스턴스를 일괄 신호하지 않는다. macOS의 신호 처리는 `os/signal`로 등록한다. [S11]

```text
파일 읽기 → 타입/호스트/고정 설정/CA 검증
         → immutable PolicySnapshot 생성
         → atomic pointer로 한 번에 교체
         → config.applied(revision, next_connections_only=true)
```

공유 map을 handler가 읽는 동안 수정하지 않는다. CONNECT admission 시점에 한 번 읽은 정책과 revision을 연결에 고정한다. 새 HTTP keep-alive 요청이 기존 TLS 연결 안에 생기는 것은 새 CONNECT가 아니다. 이 정책 교체는 Go atomic pointer로 구현할 수 있다. [S7]

**TLS 연결을 유지한 채 passthrough ↔ MITM으로 바꾸지 않는다.** 이미 생성한 터널은 그대로 종료될 때까지 기존 정책을 사용한다. 정책 변경 전에 전송한 HTTPS 본문을 사후 복호화할 수도 없다. [S1][S2]

| 변경 | 새 CONNECT | 이미 열린 연결 |
|---|---|---|
| 호스트 추가/SSL 켜기 | 대상만 MITM | 기존 터널은 그대로. 새 연결이 필요 |
| 호스트 제거/SSL 끄기 | passthrough | 기존 MITM은 종료될 때까지 유지될 수 있음 |
| reload 실패 | 마지막 정상 정책 | 변화 없음 |

P0에서는 진행 중 업로드/결제를 보호하기 위해 연결을 자동으로 끊지 않는다. 이벤트와 stderr에 `active_legacy_connections`, `active_legacy_mitm_connections`를 표시한다. 구 설정의 MITM이 남아 있으면 `SSL fully off`라고 표시하지 않는다. 즉시 전환하려면 앱이 새 연결을 만들도록 하거나 프록시를 명시적으로 재시작한다. 관찰된 새 connection ID로 확인하며, 앱 재실행만으로 모든 SDK 연결이 반드시 새로 생성된다고 보장하지 않는다.

### 4.7 사용 예 — 구현할 인터페이스

```bash
# 먼저 한 번만 로컬 CA를 생성하고, 공개 .cer의 위치를 확인한다.
mhi ca init
mhi ca path

# 출력된 .cer를 사용자가 Finder/AirDrop으로 전달한다.
# 최초에는 SSL disabled. 이후 파일의 SSL 항목만 수정한다.
mhi serve --config ./mhi.yml --watch

# .env만 관리할 수도 있다.
mhi serve --env-file ./.env --watch

# 나중에 선택할 호스트의 JSON도 볼 예정이면 시작할 때 명시한다.
# monitoring 상태에서는 이 옵션도 HTTPS 내용을 읽지 못한다.
mhi serve --config ./mhi.yml --watch --body json --details

# 파일을 읽어 유효 설정을 확인한다. 실행 중 프로세스를 제어하지 않는다.
mhi config check --config ./mhi.yml
mhi config show --config ./mhi.yml
```

### 4.8 출력 계약

```text
14:30:01 CONNECT  api.example.com:443       mode=tunnel policy=1
14:30:02 CONNECT  upload.example.com:443    mode=tunnel policy=1
14:30:03 CONNECT  thirdparty.example:443    mode=tunnel policy=1
# config 적용 안내는 stderr: revision=2; new connections only
14:30:07 CONNECT  api.example.com:443       mode=mitm phase=handshake policy=2
14:30:07 HTTPS    GET api.example.com/v1/me upstream=200 policy=2
14:30:08 CONNECT  thirdparty.example:443    mode=tunnel policy=2
```

CONNECT 횟수는 API 요청 횟수가 아니다. 터널당 요청 수·HTTP 메서드·URL path·헤더·본문·실제 API 상태 코드를 추측하지 않는다. 터널의 proxy 200은 실제 API의 HTTP 200이 아니다. CONNECT가 IP 리터럴이면 IP만 표시하며 DNS 이름/앱명을 만들어내지 않는다. [S1]

MITM 선택 이벤트와 TLS handshake 성공, HTTP 응답 성공을 구분한다. `UPSTREAM`은 실제 서버 응답만 나타내고 프록시가 생성한 407/502는 별도 필드다. stdout은 선택 형식의 정제 이벤트만, stderr는 상태·reload·경고·종료 요약만 출력한다. 인증 비밀번호는 TTY 전용이다.

text는 네트워크 유래 ESC/OSC/control character를 escape한다. JSONL에는 배너/ANSI를 섞지 않는다. 종료 코드: 0 정상, 2 잘못된 설정/필요한 CA 부재, 3 시작 실패, 4 출력 실패/관찰 손실, 130 SIGINT. reload 실패는 실행 중 프로세스를 종료하지 않고 구조화 이벤트로 보고한다.

## 5. CA: 로컬 생성과 경로 출력만

### 5.1 위치와 파일

기본 state-dir는 `os.UserConfigDir()/mhi`다. macOS의 UserConfigDir는 `$HOME/Library/Application Support`이므로 기본 설계 경로는 다음과 같다. 이것은 구현할 경로이며, 이 명세를 작성하면서 실제 CA를 생성하지는 않았다. [S6]

```text
~/Library/Application Support/mhi/          # 0700
  ca/                                      # 0700
    root-cert.cer                          # 공개 DER, AirDrop할 파일, 0600
    root-cert.pem                          # 동일한 공개 인증서의 PEM, 0600
    root-key.pem                           # PKCS#8 개인키, 절대 공유하지 않음, 0600
    metadata.json                          # 생성 방식·지문·시각·generator version
  run.lock                                 # serve/init/delete의 배타적 잠금
```

`ca init`은 stdout에 공유할 `.cer`의 절대 경로 한 줄, stderr에 생성 성공·지문·유효기간을 출력한다. `ca path`도 공개 `.cer` 절대 경로 한 줄만 반환한다. `ca status --json`은 비밀 키 내용 없이 실제 검증 결과만 반환한다. 생성/삭제 실패 시 성공 경로를 먼저 출력하지 않는다.

공개 DER는 `x509.ParseCertificate`로 인증서 하나만 포함하는지 검사하고 PEM과 DER 지문이 동일한지 확인한다. 키와 공개 인증서를 합친 PEM 또는 `.p12`를 배포하지 않는다. 인증서마다 고유 subject suffix와 serial을 사용한다.

### 5.2 로컬 생성 CA만 사용하는 정책

생성 진입점은 `mhi ca init` 하나다. Go `crypto/rand`, ECDSA P-256, `crypto/x509`로 self-signed CA를 생성한다. 제안 유효기간은 1년이며 `IsCA`, `KeyUsageCertSign`, 적절한 BasicConstraints를 설정한다. 임시 디렉터리 작성·검증 후 원자적으로 게시하고 기존 CA를 덮어쓰지 않는다. [S5]

외부 `ca-cert`/`ca-key` 경로, inline PEM 환경변수, URL, import, 기본 공유 CA fallback은 제공하지 않는다. state-dir는 앱 저장 위치만 바꾸며 임의 CA import 수단이 아니다. metadata에 `origin: mhi-local-generation`, CA 지문, 공개키 지문, generator version/생성 시각을 기록한다. 로드 시 app-owned 일반 파일·owner·permissions·self-signature·CA flag·유효기간·key match·metadata 일치를 검사한다.

이 metadata 검사는 우발적 파일 혼동을 막는 정책이지, CA의 역사적 생성 장소를 암호학적으로 입증하는 장치는 아니다. 같은 사용자/관리자가 파일과 metadata를 함께 변조한 위협까지 방어한다고 주장하지 않는다.

GoProxy의 `GoproxyCa`/기본 `MitmConnect`를 사용하지 않고 검증한 로컬 CA를 주입한 ConnectAction만 생성한다. 라이브러리에 내장 키가 존재한다는 것과 제품이 이를 사용하는 것은 다르다. 실제 제시한 leaf가 자신의 로컬 CA에만 연결되는지 fixture로 검증한다. [S2][S4]

leaf는 정확한 DNS SAN만 포함하며 CA 만료 이후로 유효하지 않다. 캐시는 CA 지문+host 기준, 최대 256개, 메모리 전용이다. TLS 프로토콜/암호 자체를 구현하지 않는다. 개인키는 파일 권한으로 보호하는 비암호화 파일이며, 0600을 암호화로 설명하지 않는다.

### 5.3 수동 전달과 신뢰 경계

사용자는 `ca path`가 출력한 `root-cert.cer`만 AirDrop한다. 제품은 AirDrop 실행·다운로드 페이지·QR·기기 프로파일·자동 설치를 제공하지 않는다. 키가 들어 있는 디렉터리 전체나 root-key.pem을 보내도록 안내하지 않는다.

전송과 인증서 설치/신뢰 활성화는 별개다. iPhone에서 수동 설치한 CA는 SSL/TLS 신뢰를 별도로 켜야 한다. 이 작업을 CLI가 완료했다고 표시하지 않는다. 상세 설치 마법사는 제품 범위 밖이며 README에 이 전제만 짧게 둔다. [S12]

Mac 키체인(login/System)과 시스템 프록시는 변경하지 않는다. `ca init`/`status`/`path`는 sudo, security add-trusted-cert, Keychain API, 브라우저 실행을 호출하지 않는다. Mac 테스트 클라이언트에는 공개 CA를 개별 요청에 명시한다.

### 5.4 실행 중 CA와 삭제

P0에서 serve는 state-dir의 run.lock을 실행 기간 동안 보유한다. ca init/delete는 동일 잠금을 요구하며 실행 중에는 거부한다. CA 없이 monitoring은 가능하지만, 그 세션에서 MITM을 켜려다 CA가 없으면 reload를 reject한다. 먼저 serve를 종료하고 init한 뒤 다시 시작한다. 일반 사용은 init을 먼저 하므로 SSL toggle마다 생성할 필요가 없다.

CA는 최초 MITM 활성화 때 검증·로드하고 해당 실행에서 같은 지문으로 유지한다. CA 교체 hot reload는 없다. 사용 중 파일 교체/만료가 발견되면 신규 MITM을 거부하고 명확한 오류를 출력한다. 내장 CA로 전환하지 않는다. 연결마다 유효기간을 확인한다. 사용자가 생성/교체한 파일이 아닌 기존 타 도구 데이터를 재사용하지 않는다.

삭제는 TTY 지문 확인 또는 `--yes --fingerprint <전체 SHA256>`를 요구한다. symlink·경로 탈출·owner·파일 종류를 검사하고 CA 파일만 삭제한 뒤 부재를 확인한다. 일부 실패는 delete_failed로 보고한다. status/path/serve는 CA를 자동 재생성하지 않는다.

CA 파일 삭제가 iPhone 신뢰의 원격 취소는 아니다. iPhone 프로파일 제거는 사용자가 한다. 백업·SSD·스냅샷의 물리적 삭제를 보장하지 않는다. 기존 Proxyman CA·다른 앱의 파일·키체인을 건드리지 않는다.

## 6. CONNECT 모니터링과 대상 정책

IP/proxy auth 검사는 host 모니터링 및 upstream dial보다 먼저 수행한다. 승인된 연결에 한해서 CONNECT authority, connection ID, 관찰 시각, mode와 정책 revision을 기록한다. 거부된 접속은 제한된 오류 코드만 남긴다. 도메인 메타데이터 자체도 민감할 수 있으므로 원격 업로드/기본 파일 저장은 하지 않는다.

CONNECT의 host:port를 엄격히 파싱한다. MITM 목록은 ASCII/punycode DNS 호스트와 포트, 포트 생략 시 443만 지원한다. 대소문자와 종단 dot을 일관되게 정규화하고 전체 호스트/포트를 비교한다. CONNECT의 잘못된 authority/port는 기본 80 등으로 추측하지 않고 거부한다. IP 리터럴은 tunnel discovery에서만 지원하고 P0 IP-SAN MITM은 제외한다. [S1]

```text
인증/IP/목적지 허용 실패 → reject
허용됨 + SSL disabled → tunnel + CONNECT metadata
허용됨 + SSL enabled + exact host match + local CA ready → MITM
허용됨 + SSL enabled + host not matched → tunnel + CONNECT metadata
선택 호스트지만 CA 오류 → 명시적 오류; 내장 CA/fallback MITM 없음
```

목록은 복호화 허용 목록이지 연결 허용 목록이 아니다. 비대상 호스트를 차단하지 않는다. 다만 공용 프록시 악용을 막는 별도 목적지 정책은 유지한다. P0의 CONNECT는 443과 사용자가 SSL 대상에 명시한 추가 TLS 포트만 허용한다. SMTP 등 임의 TCP 포트는 기본 거부한다. [S1]

localhost/loopback/link-local/private/multicast/메타데이터 주소는 outbound에서 기본 차단한다. DNS 검증 후 같은 검증 IP로 dial하고 HTTP/MITM/CONNECT 경로에 일관되게 적용한다. 사설 API는 후속 범위다. 테스트 fixture에는 격리된 dial 의존성을 주입하며 제품 기본값을 완화하지 않는다.

MITM에서는 CONNECT authority, TLS SNI, 내부 HTTP Host를 동일 목적지에 고정한다. 내부 Host 변경으로 비대상 도메인에 접근하지 못하게 한다. CONNECT 정책 결정 시점의 snapshot을 사용해 reload가 진행 중인 handshake를 다른 정책으로 바꾸지 않는다.

일반 tunnel에서는 TLS를 종료하지 않고 client/server의 검증에 맡긴다. 프록시가 tunnel 내부 서버 인증서를 검증하거나 앱의 요청 성공을 확인했다고 표시하지 않는다. TLS 핀닝은 제품이 우회하지 않는다. MITM 오류 후 자동 tunnel retry도 추가하지 않는다. 사용자가 목록에서 빼고 새 연결로 재시도한다.

HTTP 평문은 별도의 `http_capture.domains`에 포함된 경우만 상세 관찰한다. 비대상 HTTP가 내부 파싱된다는 것과 캡처에 저장한다는 것을 구별한다. 전체 모니터링은 모든 앱·모든 네트워크 트래픽 감시가 아니라, 이 프록시를 실제 통과한 승인 기기의 CONNECT 관찰이다.

## 7. 스트리밍 관찰과 정제

### 7.1 요청을 읽는 방식

`io.ReadCloser` 래퍼로 전달 중인 request/response body의 복사본만 제한적으로 관찰한다. 본문을 `io.ReadAll`로 먼저 소비한 뒤 재주입하는 구현은 금지한다. Read/Close 오류·EOF·취소를 구별하고 업로드와 다운로드 완료 상태를 독립적으로 관리한다.

`Close()` 호출만으로 본문 수신 완료라고 표시하지 않는다. EOF 또는 길이 검증 등 관찰 가능한 근거를 사용한다. Transport의 request body Close가 비동기일 수 있으므로 읽기·close·종료 상태에 race가 없어야 한다. 서버가 업로드 도중 413을 반환해도 영구 대기하지 않는다.

헤더 후킹 시점은 응답 완료 시점이 아니다. 응답 헤더 수신 때 `flow.response_headers`, 본문 read 종료 때 `flow.finished` 또는 오류를 기록한다. 이 종료는 프록시 관찰 완료이며 클라이언트 애플리케이션 수신 확인이 아니다.

### 7.2 제한값 — 구현 목표

| 항목 | 기본 상한/정책 |
|---|---|
| 본문 모드 | none |
| json 모드 MIME | application/json, application/*+json |
| encoded 관찰 버퍼 | request/response 각각 256 KiB |
| decoded JSON 입력 | 각각 256 KiB; gzip은 별도 해제 한도 |
| 정제 preview | 각각 64 KiB; 초과 시 원문/잘린 JSON 대신 생략 |
| 전체 미정제/분석 버퍼 | 총 16 MiB. 예산 확보 실패 시 해당 body 생략 |
| 출력 이벤트 큐 | 1,024개 또는 8 MiB 중 먼저 도달하는 한도 |
| 헤더 관찰 사본 | 방향별 32 KiB. 초과는 관찰에서만 생략 |
| 동시 관찰 flow | 128개. 초과는 관찰 생략과 손실 통계 |
| 파일 | 명시적으로 생성한 JSONL 하나, 기본 100 MiB 상한 |

일반 JSON 파싱/정제는 bounded worker에서 처리한다. 원문 버퍼를 worker에 넘기는 경계는 내부 비신뢰 관찰 단계이며, 공용 이벤트 큐에는 정제 완료 타입만 들어간다. CPU가 오래 걸리는 파싱 때문에 실제 전달 goroutine을 대기시키지 않는다. 과도한 중첩·토큰 수에도 한도를 둔다.

multipart/동영상/바이너리/HTML/form/SSE는 P0에서 본문 저장 없이 타입·관찰 바이트 수·오류·타이밍만 기록한다. gzip 외 압축은 P0에서 `unsupported_encoding`으로 생략한다. 길이 초과·파싱 실패·압축 해제 실패·정제 실패에서 원문 fallback은 없다.

### 7.3 정제 정책

기본 헤더 관찰은 content-type, content-length 등 제한된 allowlist를 사용한다. `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API key 계열은 항상 값이 제거된다. custom correlation header는 사용자가 비민감 필드임을 확인해 규칙에 추가한다.

query 값은 기본 마스킹, path는 프로젝트별 민감 세그먼트 규칙을 적용한다. json 모드는 기본적으로 key 이름 기반 secret/token/password 차단을 적용하고, stricter 모드에서는 지정 JSON Pointer의 scalar 값만 보인다. object/array pointer를 허용했다고 하위 값을 전부 통과시키지 않는다.

키 이름 규칙만으로 모든 개인정보를 제거한다고 보장하지 않는다. json 모드 활성화 시 이 한계를 표시한다. 프로덕션 데이터에서는 strict 모드와 테스트 계정을 우선한다. query key/path 자체도 식별정보일 수 있으며 공유 전 검토가 필요하다.

`redact-rules.json` 제안 계약:

```json
{
  "schema_version": 1,
  "json_mode": "strict",
  "json_allow_pointers": ["/error/code", "/requestId"],
  "extra_secret_keys": ["accessToken", "refreshToken"],
  "query_allow_keys": [],
  "header_allow_names": ["content-type", "content-length", "x-request-id"],
  "path_rules": [
    {"pattern": "^/users/[^/]+", "replacement": "/users/[redacted]"}
  ]
}
```

정제는 원본 request/response의 사본에만 적용한다. upstream 인증값/본문은 유지한다. hop-by-hop 및 proxy 전용 헤더 제거, HTTP 프레이밍/대소문자/헤더 순서 변경 등 프록시가 수행하는 정규화까지 byte-for-byte 보존한다고 주장하지 않는다.

앱 차원의 재전송/재시도는 추가하지 않는다. 다만 Go Transport 자체의 제한적 재시도 조건이 존재하므로 네트워크 요청 전체에 대한 exactly-once 전달을 보장하지 않는다. 인증된 POST가 임의 중복 실행되지 않는 fixture를 포함한다. [S13]

## 8. Go 타입과 JSONL 계약

JSONL은 `schema_version: 2`의 이벤트 스트림이다. 문서 버전 v0.3, YAML schema_version 1, 이벤트 schema_version 2는 별개다. v0.2 초안에서 connection/config 정책 필드가 추가되어 이벤트 버전을 구분한다. 정제 타입에는 raw http.Request/Response, 원문 에러, CA 키를 넣지 않는다.

```go
// 필수 계약의 요약. 필드별 상세 검증은 JSON Schema/fixture로 고정한다.
type SafeEvent struct {
    SchemaVersion int             `json:"schema_version"`
    RunID         string          `json:"run_id"`
    Seq           uint64          `json:"seq"`
    Type          string          `json:"type"`
    At            time.Time       `json:"at"`
    PolicyRevision uint64         `json:"policy_revision,omitempty"`
    Connection    *SafeConnection `json:"connection,omitempty"`
    Config        *SafeConfigEvent `json:"config,omitempty"`
    Flow          *SafeFlow       `json:"flow,omitempty"`
    Diagnostic    *SafeDiagnostic `json:"diagnostic,omitempty"`
}

type SafeFlow struct {
    ID               string       `json:"id"`
    ConnectionID     string       `json:"connection_id"`
    PolicyRevision   uint64       `json:"policy_revision"`
    Method           string       `json:"method"`
    Host             string       `json:"host"`
    Port             int          `json:"port"`
    Path             string       `json:"path"`
    UpstreamStatus   *int          `json:"upstream_status"`
    DownstreamStatus *int          `json:"downstream_status"`
    State            string       `json:"state"`
    Request          SafeSide     `json:"request"`
    Response         SafeSide     `json:"response"`
    DurationMS       *float64     `json:"duration_ms"`
    ErrorCode        string       `json:"error_code,omitempty"`
    Incomplete       bool         `json:"incomplete"`
}

type SafeSide struct {
    HeadersSeen   bool       `json:"headers_seen"`
    EOFObserved   bool       `json:"eof_observed"`
    HTTPVersion   string     `json:"http_version,omitempty"`
    Headers       []SafePair `json:"headers"`
    ObservedBytes int64      `json:"observed_bytes"`
    BodyState     string     `json:"body_state"`
    Omission      string     `json:"omission,omitempty"`
    Preview       string     `json:"preview,omitempty"`
}

type SafePair struct { Name string `json:"name"`; Value string `json:"value"` }
type SafeDiagnostic struct {
    Code         string `json:"code"`
    ConnectionID string `json:"connection_id,omitempty"`
    Count        uint64 `json:"count,omitempty"`
}
```

헤더의 여러 값은 유지하되, Go의 HTTP 표현에서 원래 wire상의 순서·대소문자를 복원했다고 표시하지 않는다. 위 요약에서 생략한 query·세부 타이밍 등의 DTO는 M0에서 추가 정의한다.

이벤트는 `capture.started`, `connection.opened`, `connection.mode_selected`, `connection.tunnel_ready`, `connection.closed`, `connection.error`, `flow.request_headers`, `flow.response_headers`, `flow.finished`, `config.applied`, `config.rejected`, `config.shadowed`, `capture.loss`, `capture.finished`다. HTTP 오류 응답도 flow.finished에 포함하며 실제 응답이 없으면 upstream_status=null이다.

SafeConnection은 id/client/host/port/mode/policy_revision/phase/started_at/closed_at 및 proxy_connect_status를 포함한다. 터널 이벤트에는 내부 HTTP path/method/body/upstream_status를 채우지 않는다. 실제 측정하지 않은 바이트 수나 요청 수를 만들지 않는다. config 이벤트는 revision과 변경 호스트, new_connections_only, legacy 연결 수, 구조화 오류만 포함하고 환경변수/개인키/원문 파일을 포함하지 않는다.

연결의 mode와 policy_revision은 생성 후 불변이다. MITM TLS 안의 여러 HTTP flow는 같은 revision을 사용한다. watcher가 정책을 교체하더라도 기존 연결 이벤트를 새 revision으로 덮어쓰지 않는다.

Seq는 직렬 enqueue 단계에서 부여해 출력 순서대로 단조 증가시킨다. drop도 번호를 소비하며, 출력 회복 시 capture.loss에 누락 건수를 기록한다. 종료까지 출력이 불가능하면 stderr와 종료 코드에 손실을 표시한다. 장시간 스트림도 headers 이벤트를 먼저 보내 종료 전까지 모든 정보를 숨기지 않는다.

observed_bytes는 래퍼가 읽은 애플리케이션 본문 바이트 수다. TLS wire bytes나 서버·앱 도달 확인이 아니다. duration은 Go의 monotonic clock을 활용한 프록시 관찰 시간이며, 측정하지 못한 값을 0으로 채우지 않는다.

## 9. 오류·출력·종료 처리

### 9.1 오류 분류

`proxy_auth_failed`, `destination_denied`, `name_resolution_failed`, `connect_failed`, `upstream_tls_failed`, `client_tls_failed`, `read_failed`, `client_disconnected`, `interrupted`, `unknown`을 사용한다. 설정/CA 진단은 `config_invalid`, `config_restart_required`, `config_shadowed`, `ca_missing`, `ca_invalid`, `ca_expired`, `ca_origin_unverified`를 별도로 둔다.

라이브러리에서 구조화된 근거를 얻을 수 있을 때만 구체적으로 분류한다. client TLS handshake 오류를 가져올 지점이 없으면 생로그를 분석해 Pinning으로 확정하지 않고 unknown과 관찰 한계를 기록한다. Pinning은 가능한 원인이지 오류 코드만으로 확정하는 사실이 아니다.

서버의 500, 프록시가 생성한 502, 클라이언트의 TLS 거부를 구별한다. M0에서 upstream 인증서 불량과 client CA 미신뢰를 별도 fixture로 재현한다.

### 9.2 출력 실패

출력은 전용 goroutine과 bounded queue에서 처리한다. 느린 terminal/file 때문에 request 처리를 대기시키지 않는다. 파일은 0600, 배타적 생성, 일반 파일만 허용하고 기존 파일/symlink는 거부한다. --output 없이 프로그램이 세션 파일을 자동 생성하지 않는다. 다만 사용자가 stdout을 redirect한 기록은 사용자 관리 범위다.

디스크가 가득 차거나 용량 상한에 도달하면 해당 파일 sink를 중지하고 stderr에 경고하되 프록시는 계속 전달한다. 다른 생로그로 fallback하지 않는다. stdout의 broken pipe는 제어된 프록시 종료로 처리한다. Go의 SIGPIPE 동작을 고려해 EPIPE 감지와 종료를 테스트한다. 출력이 회복되지 않으면 완전한 JSONL 마지막 이벤트를 보장하지 않고 종료 결과로 알린다.

### 9.3 Ctrl+C / SIGTERM

새 accept 중지 → 기존 요청에 3초의 정리 시간 제공 → 남은 연결 명시 close → idle upstream 연결 close → 관찰 worker/출력의 제한된 종료 대기 → 종료 요약 순서로 처리한다.

**http.Server.Shutdown만 호출하면 CONNECT/MITM 연결도 닫힌다고 가정하지 않는다.** Go의 Shutdown은 hijack된 연결을 기다리거나 닫지 않는다. accepted/outbound net.Conn을 registry로 추적해 Hijack 이후에도 소유 연결을 종료할 수 있어야 한다. ResponseWriter 래퍼는 필요한 Hijacker/Flusher 기능을 보존한다. [S13]

프로그램 종료는 CA 삭제나 iPhone 신뢰 해제가 아니다. iPhone Wi-Fi 프록시를 끄고, 필요에 따라 CA 신뢰 해제/프로파일 제거를 수행하도록 stderr에 안내한다. 데몬과 자동 재시작은 구현하지 않는다. SIGKILL 후에는 OS가 프로세스의 연결을 정리하지만, 파일 마지막 줄과 종료 이벤트는 불완전할 수 있다.

## 10. 권장 디렉터리

```text
mobile-http-inspector/
  cmd/mhi/main.go
  internal/
    cli/            # cobra commands, flags, exit status
    config/         # YAML/env/flags, provenance, validation, reload coordinator
    policy/         # immutable connection policy, exact host matching
    ca/             # local create/load/path/delete, lock, permissions
    proxy/          # GoProxy adapter, TLS, auth, destination policies
    capture/        # bounded ReadCloser, lifecycle, body budgets
    redact/         # safe copies, strict JSON pointers, terminal escaping
    model/          # SafeEvent, SafeFlow, typed diagnostics
    output/         # text, JSONL, file sinks, loss accounting
    lifecycle/      # contexts, connection registry, shutdown
  testdata/         # non-secret fixtures and golden JSONL
  tests/integration/
  docs/specification.md
  examples/mhi.yml
  examples/.env.example
  docs/ca-files.md
  docs/verification-matrix.md
  go.mod
  go.sum
  Makefile
```

큰 범용 프레임워크나 plugin 구조를 만들지 않는다. 인터페이스는 CA store, proxy adapter, sink, 필요한 clock/dial 의존성에 한정한다. 모든 패키지를 외부에 공개하는 pkg 구조는 필요하지 않다.

## 11. 수용 테스트

아래는 구현 요구사항이며 아직 수행한 제품 테스트 결과가 아니다.

| ID | 테스트 | 통과 조건 |
|---|---|---|
| AC-01 | 첫 실행/help/status/path | CA 자동 생성·sudo·키체인/프록시 변경 없음. 없는 공개 파일은 nonzero |
| AC-02 | 로컬 독립 CA | state-dir별 키/지문이 다르고 제시 leaf가 내장 CA가 아닌 자신의 CA로 검증 |
| AC-03 | iPhone HTTPS | 공개 .cer 수동 전달 후 Mac 신뢰 없이 iPhone만 신뢰해 선택 호스트 관찰 |
| AC-04 | 비대상 도메인 | MITM 인증서 제시 없음. CONNECT metadata만, 내부 내용 출력 없음 |
| AC-05 | matcher | 유사 호스트·subdomain·port·wildcard·URL 입력·SNI/Host 우회 방지 |
| AC-06 | upstream 검증 | MITM에서 불량/만료/hostname 불일치 서버 인증서 거부 |
| AC-07 | client CA 거부 | HTTP 500/Pinning 확정으로 오표시하지 않고 자동 우회/재시도 없음 |
| AC-08 | 승인 외 연결 | 잘못된 peer/auth로 dial/상세 관찰 불가 |
| AC-09 | 공개 CA 경로 | init이 공개 DER/PEM과 별도 key 생성. path는 공개 DER만 반환, 개인키 미포함 |
| AC-10 | 대용량 | 1 GiB 전달에 전체 버퍼링·비례 메모리 증가 없음 |
| AC-11 | 조기 413/취소 | request/response 순서 고정 가정 없음. EOF/Close/취소 구분 |
| AC-12 | JSON/gzip 한도 | 잘못된/과도한 입력에 원문 fallback 없음 |
| AC-13 | canary secret | stdout/stderr/file/library/config 진단에 token/cookie/key 내용 없음 |
| AC-14 | 전달 의미 | 앱 인증정보/body 유지. Proxy-Authorization 제거 |
| AC-15 | HTTP 의미 | 실제 API 상태와 proxy CONNECT 200/407/502 구분, gzip/HEAD/중복 헤더 |
| AC-16 | slow sink | 네트워크가 출력 대기를 하지 않고 loss/불완전 표시 |
| AC-17 | 종료 | keepalive/CONNECT/MITM/stream, watcher, worker 정리; 소유 연결 누락 없음 |
| AC-18 | CA 삭제 | 사용 중 거부·부분 실패 보고·부재 확인·자동 재생성 금지 |
| AC-19 | 시스템 불변 | login/System 키체인·시스템 프록시·기존 Proxyman 파일 불변 |
| AC-20 | terminal 안전 | ESC/OSC/control 문자열이 터미널 제어를 실행하지 않음 |
| AC-21 | JSONL | schema_version 2, seq/connection revision/status null 일관성, 배너 없음 |
| AC-22 | 파일 실패 | 0600·배타 생성·symlink 거부·ENOSPC/상한/EPIPE 처리 |
| AC-23 | 환경 프록시 | HTTP_PROXY/HTTPS_PROXY로 자기 재귀/우회 없음 |
| AC-24 | 목적지 제한 | private/link-local/DNS rebinding/비허용 CONNECT 포트 차단 |
| AC-25 | race | handler/reload/Read/Close/shutdown 경쟁에 go test -race 통과 |
| AC-26 | clean Mac | Go compiler/Python/Node/Homebrew 없이 단일 바이너리 실행 |
| AC-27 | 순수 모니터링 | CA 없음+SSL false+빈 목록으로 실행, host:port만 확인, CA 생성 없음 |
| AC-28 | SSL 켜기 | YAML/.env 수정 후 새 대상 CONNECT만 MITM, 그 외 tunnel |
| AC-29 | 기존 터널 | 추가 후 기존 연결은 tunnel 유지, 새 connection ID만 새 revision/MITM |
| AC-30 | SSL 끄기 | 새 CONNECT는 tunnel, 기존 MITM 수 경고, 자동 절단/fully-off 오표시 없음 |
| AC-31 | 잘못된 reload | 문법 오류/true+빈 목록/CA 없음이면 직전 정책·revision 유지, 상태 명시 |
| AC-32 | 설정 우선순위 | flag/env/.env/YAML/default, false/빈 목록 구분, list replace, shadow 경고 |
| AC-33 | env 재읽기 | .env 변경이 이전 Load 값에 막히지 않으며 프로세스 환경을 변경하지 않음 |
| AC-34 | 파일 watch | atomic rename/delete/recreate/연속 저장/overflow/SIGHUP 처리; last-good 보존 |
| AC-35 | 고정 필드 변경 | listener/client/CA/output 등의 변경을 부분 적용하지 않고 재시작 필요로 거부 |
| AC-36 | 로컬 CA 정책 | 외부 CA flag/env/import 없음; 생성 metadata/key/cert 불일치·만료·symlink 거부 |
| AC-37 | 설치 표면 제거 | `/ca`, `/install` 등 다운로드 handler·디렉터리 서버·QR·키체인 설치 없음 |
| AC-38 | 설정 입력 안전 | unknown/duplicate/YAML alias/다중 문서/잘못된 타입/.env 확장/파일 한도 거부 |

관찰 가능한 사실만 테스트 결과로 표시한다. AirDrop 수신·iPhone 신뢰·app Pinning·proxy 우회·미검증 HTTP/2 클라이언트 동작은 자동 fixture와 구별해 실기기 검증표에 기록한다.

## 12. 구현 순서와 게이트

### M0 — CA 없는 도메인 모니터링

Go/Cobra scaffold, config decoder/validator, 승인 IP/proxy auth, 목적지 제한, CONNECT passthrough, text 연결 metadata, 연결 registry와 Ctrl+C 종료를 구현한다. 기본값은 SSL false/빈 목록이다. CA·MITM을 만들기 전에 이 경로가 동작해야 한다.

**게이트:** AC-01/08/15/17/23/24/27 최소 테스트. 본문·TUI보다 먼저 검증한다.

### M1 — 로컬 CA와 선택적 MITM

ca init/path/status, 공개 DER+PEM/별도 key, CA origin 정책, TLS 검증 transport, exact matcher, iPhone 수동 전달을 구현한다. 정적 설정으로 선택 호스트만 복호화한다.

**게이트:** AC-02/03/04/05/06/07/09/19/36/37. CA 다운로드 기능을 추가하지 않는다.

### M2 — 파일 설정 reload

YAML/.env precedence/provenance, immutable snapshot, directory watcher/SIGHUP, last-known-good, 새 CONNECT 적용, legacy 연결 수, 고정 필드 reject를 구현한다.

**게이트:** AC-25/28/29/30/31/32/33/34/35/38. 계속 열린 tunnel에서 즉시 복호화가 된 것처럼 테스트하지 않는다.

### M3 — 정제 관찰과 파일

bounded ReadCloser, JSON/압축 한도, safe event, 정제 규칙, text/details/JSONL, 제한된 file sink, loss, CA 삭제/잠금/doctor를 구현한다.

**게이트:** AC-10/11/12/13/14/16/18/20/21/22/25.

### M4 — 실기기·배포 검증

단일 arm64 바이너리, checksum/license/dependency/security 검사, clean Mac, AirDrop 수동 전달, Wi-Fi 변경/sleep-wake, app 재연결, long-lived tunnel과 reload를 검증한다. 외부 배포 서명/공증은 별도 검증한다.

**게이트:** AC-26 및 전체 AC를 pass/fail/not-tested로 기록. 실제 실행하지 않은 결과를 통과로 처리하지 않는다.

성능 목표는 미측정 제안값이다. 로컬 fixture 10 KiB JSON 50 req/s 5분, 1 GiB streaming, 동시 policy reload의 RSS/queue/loss/latency를 측정한다. 예산 초과 관찰 생략은 명시하고 원본 요청을 변조해 해결하지 않는다.

## 13. 구현 에이전트 시작 지시

> 이 v0.3만 구현 기준으로 사용한다. Go 단일 CLI로 M0의 CA 없는 CONNECT 도메인 모니터링부터 만든다. YAML/.env는 명시적 경로로 읽고 SSL false/빈 목록을 정상 상태로 허용한다. 뒤이어 로컬 ca init/path, 선택 호스트 MITM, 원자적 정책 reload를 구현한다. 새 CONNECT에서만 정책을 선택하고 기존 TLS 터널을 중간에 전환하지 않는다. 기존 MITM이 남아 있는데 완전히 꺼졌다고 표시하지 않는다. GoProxy 내장 CA/외부 CA import/fallback, CA 다운로드 서버, 설치 마법사, Mac 키체인·시스템 프록시 변경, 원문 로그, Pinning 우회, 자동 요청 재전송, GUI/TUI를 추가하지 않는다. 실제 수행한 테스트 결과와 실기기 미검증을 구분한다. 기본 upstream TLS 검증·환경 proxy 비사용·원본 의미 보존·bounded capture·hijacked 연결 종료를 유지한다.

## 14. 일차 자료와 설계 판단

확인일: 2026-10-30. CLI/파일명/상한/reload 정책은 본 프로젝트의 설계 계약이며, 아래 자료가 제품 구현 완료를 뜻하지 않는다. 원문 v0.2에서 요구사항을 보존한 뒤 v0.3 변경을 적용했다.

| ID | 자료 | 근거 |
|---|---|---|
| S1 | RFC 9110 §9.3.6 | CONNECT 목적지/터널 의미, TCP 포트 제한 |
| S2 | GoProxy v1.9.2 https.go | ConnectAccept/ConnectMitm, 연결 시 분기, 사용자 TLSConfig |
| S3 | GoProxy v1.9.2 proxy.go | transport 기본값·환경 proxy·custom transport |
| S4 | GoProxy v1.9.2 certs.go | 내장 CA/키와 사용자 CA 대체 |
| S5 | Go crypto/x509 | 로컬 인증서 생성/파싱 |
| S6 | Go os.UserConfigDir | macOS Application Support 위치 |
| S7 | Go sync/atomic | immutable policy pointer 교체 |
| S8 | joho/godotenv README | map으로 파싱, 환경변수 우선순위 |
| S9 | Go YAML v3 | Decoder.KnownFields, decoder 검증 |
| S10 | fsnotify README | atomic replace와 부모 디렉터리 감시 |
| S11 | Go os/signal | SIGHUP 등 신호 전달 |
| S12 | Apple 수동 인증서 신뢰 | 전달/설치와 SSL 완전 신뢰는 별개 |
| S13 | Go net/http | transport/body/shutdown/hijack 동작 |

```text
[S1] https://www.rfc-editor.org/rfc/rfc9110.html#name-connect
[S2] https://raw.githubusercontent.com/elazarl/goproxy/v1.9.2/https.go
[S3] https://raw.githubusercontent.com/elazarl/goproxy/v1.9.2/proxy.go
[S4] https://raw.githubusercontent.com/elazarl/goproxy/v1.9.2/certs.go
[S5] https://pkg.go.dev/crypto/x509
[S6] https://pkg.go.dev/os#UserConfigDir
[S7] https://pkg.go.dev/sync/atomic
[S8] https://github.com/joho/godotenv
[S9] https://pkg.go.dev/go.yaml.in/yaml/v3
[S10] https://github.com/fsnotify/fsnotify
[S11] https://pkg.go.dev/os/signal
[S12] https://support.apple.com/ko-kr/102390
[S13] https://pkg.go.dev/net/http
```
