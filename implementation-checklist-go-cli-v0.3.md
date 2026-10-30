# Mobile HTTP Inspector — Go CLI 구현 작업 목록 v0.3

작성일: 2026-10-30 (KST)

기준: `mobile-http-inspector-go-cli-spec-v0.3.md`. 기존 v0.2 작업 목록을 대체한다. 모든 체크박스는 미완료다. 명세·예시 파일 작성과 프록시 제품 구현/실기기 검증을 혼동하지 않는다.

## 고정된 요구사항

Go 단일 바이너리 CLI. 기본은 CA 없는 CONNECT 도메인 모니터링. 사용자가 YAML/`.env`에서 지정한 도메인만 새 연결부터 SSL Proxying. 로컬 `ca init`만 허용하고 공개 `.cer`의 경로만 알려준다. AirDrop과 iPhone 신뢰 설정은 사용자가 직접 수행한다. 다운로드 endpoint, QR, 설치 마법사, CA import, 공유/내장 CA 사용, Mac 키체인 변경은 만들지 않는다.

## M0 — 복호화 없는 모니터링

- [ ] T-001: Go/Cobra/GoProxy와 필요한 config 라이브러리 버전·라이선스를 고정한다. v1.9.2는 소스 검토 기준이지 자동 최신 선택이 아니다.
- [ ] T-002: cmd/mhi, internal/cli/config/policy/proxy/model/output/lifecycle을 구성하고 help/version의 무부작용을 테스트한다. (AC-01)
- [ ] T-003: YAML과 `.env`의 명시적 경로만 읽는 typed config loader를 구현한다. 빈 SSL 목록과 false를 정상 기본값으로 둔다. (AC-27)
- [ ] T-004: listen/client/proxy auth를 구현한다. 인증 비밀번호는 TTY 또는 0600 파일만 사용하고 잘못된 peer/auth는 dial 전에 거부한다. (AC-08)
- [ ] T-005: HTTP/CONNECT 양쪽에서 환경 proxy 상속을 제거하고 DNS/IP/포트 목적지 제한을 구현한다. (AC-23/24)
- [ ] T-006: CONNECT authority를 host:port로 파싱해 mode=tunnel 메타데이터를 출력한다. CONNECT 건수를 HTTP 요청 수라고 표시하지 않는다. (AC-15/27)
- [ ] T-007: accepted/outbound/hijacked 연결 registry와 Ctrl+C/SIGTERM 정리를 구현한다. (AC-17)
- [ ] T-008: CA 없는 실행에서 인증서 자동 생성·TLS 종료·원문 터널 저장이 없음을 검증한다. (AC-01/27)

**게이트:** CA 없이 실제 iPhone/Safari의 프록시 연결 호스트가 보이고 종료 후 리스너/소유 연결이 남지 않는다. 실기기가 없으면 자동 테스트 결과와 미검증 상태를 구분한다.

## M1 — 로컬 CA와 선택적 MITM

- [ ] T-101: ca init이 독립 ECDSA 키/CA와 공개 DER `.cer` 및 PEM을 생성하도록 구현한다. 기존 파일 덮어쓰기·내장 CA 사용 없음. (AC-02)
- [ ] T-102: ca path는 공개 `.cer` 절대 경로만 stdout으로 출력하고 부재 시 nonzero 종료한다. 파일에는 인증서 하나만 있으며 key가 없음을 파싱 검사한다. (AC-09)
- [ ] T-103: metadata(origin/fingerprint/generator), 소유권/권한/key match/CA flag/self-signature/유효기간 검증을 구현한다. provenance의 한계를 문서화한다. (AC-36)
- [ ] T-104: 외부 CA flag/env/import와 다운로드·QR·설치 코드를 제공하지 않는다. unknown CA config key는 거부한다. (AC-36/37)
- [ ] T-105: 정확한 DNS host:port matcher를 구현한다. wildcard·유사 hostname·scheme/path·잘못된 포트를 거부한다. (AC-05)
- [ ] T-106: local CA를 명시적으로 주입한 ConnectAction과 검증된 upstream transport를 사용한다. default MitmConnect/GoproxyCa fallback이 없도록 테스트한다. (AC-02/06)
- [ ] T-107: CONNECT/SNI/inner Host를 동일 목적지로 고정하고 로컬 CA에만 연결되는 leaf chain을 검증한다. (AC-05)
- [ ] T-108: SSL true+빈 목록/CA 없음이면 거부하고, SSL false에서는 CA 없이 통과시킨다. false+보관된 유효 목록도 테스트한다. (AC-27/31)
- [ ] T-109: 공개 `.cer`를 수동 AirDrop한 iPhone에서만 CA를 신뢰해 대상 HTTPS를 확인한다. Mac keychain은 바꾸지 않는다. (AC-03/19)
- [ ] T-110: CA 미신뢰, pinning fixture, upstream 불량 인증서를 구별한다. 자동 tunnel retry나 Pinning 확정 진단을 하지 않는다. (AC-04/06/07)

**게이트:** 비대상은 CONNECT 메타데이터만, 대상은 로컬 CA로 복호화한다. CA 전송/설치는 CLI가 수행하지 않는다.

## M2 — config/.env 재읽기와 정책 전환

- [ ] T-201: CLI > 시작 환경 > .env > YAML > defaults를 구현한다. flag의 Changed 여부, false/빈 값, list 전체 교체를 검증한다. (AC-32)
- [ ] T-202: `.env`는 map으로 매번 파싱하고 os.Setenv/Load의 잔류값에 의존하지 않는다. literal subset·중복 key·확장 금지를 검증한다. (AC-33/38)
- [ ] T-203: YAML unknown/duplicate/null/type/alias/merge/multidoc, 64 KiB/128-domain 한도를 검사한다. (AC-38)
- [ ] T-204: config check/show, 필드 출처, 정제된 config.shadowed 경고를 구현한다. show는 실행 중 프로세스의 live state를 읽는 기능이 아님을 표시한다. (AC-13/32)
- [ ] T-205: 부모 디렉터리 watch와 대상 basename filtering, debounce를 구현한다. atomic rename/delete/recreate를 테스트한다. (AC-34)
- [ ] T-206: SIGHUP과 watch를 단일 reload coordinator로 처리한다. 오류·overflow·읽기 실패에는 last-known-good와 명확한 경고를 유지한다. (AC-31/34)
- [ ] T-207: immutable PolicySnapshot을 atomic pointer로 한 번에 publish한다. handler가 공유 map을 수정하지 않는다. (AC-25/28)
- [ ] T-208: hot 필드를 SSL enabled/domains로 제한한다. listen/client/CA/output/정제 규칙 변경은 전체 후보를 거부하고 재시작 필요를 표시한다. (AC-35)
- [ ] T-209: CONNECT 시 policy revision을 고정하고 기존 tunnel/기존 MITM에서 설정이 중도 변경되지 않음을 검증한다. (AC-29/30)
- [ ] T-210: legacy 연결 수와 legacy MITM 연결 수를 출력한다. SSL false 적용 후에도 기존 MITM이 남으면 fully off라고 표시하지 않는다. (AC-30)
- [ ] T-211: false→선택 MITM→다시 false 전체 흐름을 YAML/.env 각각 테스트한다. 새 connection ID를 명시적으로 생성해 전환을 확인한다. (AC-28/29/30)
- [ ] T-212: 잘못된 파일/CA 없음/true+빈 목록/중복 저장/CLI shadow/병렬 CONNECT+reload를 회귀 테스트한다. (AC-25/31/32/34)

**게이트:** 프록시 프로세스/인증 비밀번호를 바꾸지 않고 새 연결의 정책만 변경된다. 과거 암호문을 사후 복호화하지 않으며 기존 요청을 자동 취소하지 않는다.

## M3 — 정제 본문, 출력, CA 삭제

- [ ] T-301: schema_version 2 SafeEvent/SafeFlow/SafeConnection/SafeConfigEvent와 golden fixture를 정의한다. 연결 revision과 실제 status를 구분한다. (AC-21)
- [ ] T-302: bounded ReadCloser와 request/response 독립 lifecycle을 구현한다. headers hook을 완료 이벤트로 착각하지 않는다. (AC-11)
- [ ] T-303: 1 GiB/길이 미상/조기 413/HEAD/204/304/gzip/취소/중복 헤더를 검증한다. (AC-10/11/15)
- [ ] T-304: encoded/decoded/preview/global budget, MIME 검사, JSON/gzip 실패 시 원문 fallback 금지를 구현한다. (AC-12)
- [ ] T-305: headers/query/path/JSON 정제와 strict JSON Pointer 규칙을 구현한다. 사용자 앱의 Authorization/Cookie/body를 바꾸지 않는다. (AC-14)
- [ ] T-306: canary secret을 stdout/stderr/library logger/config diagnostics/파일 sink에서 검사한다. (AC-13)
- [ ] T-307: text/details/JSONL, ESC/OSC escape, seq 직렬화와 정제 이벤트만 출력하는 경계를 구현한다. (AC-20/21)
- [ ] T-308: bounded queue/nonblocking publisher/capture.loss와 slow sink 처리를 구현한다. (AC-16)
- [ ] T-309: --output의 0600/exclusive create/symlink 거부/100 MiB/ENOSPC/EPIPE와 종료 코드를 검증한다. (AC-22)
- [ ] T-310: run.lock, 실행 중 init/delete 거부, CA 만료/key 교체의 안전 오류, leaf cache/유효기간을 구현한다. (AC-18/36)
- [ ] T-311: ca delete의 fingerprint 확인/부분 실패/부재 확인/자동 재생성 방지와 doctor의 읽기 전용 동작을 구현한다. (AC-01/18)
- [ ] T-312: 키체인·시스템 프록시·기존 Proxyman 파일 불변을 전후 검증하고 iPhone 수동 정리와 local delete를 구별한다. (AC-19)

**게이트:** 정제·출력 실패가 원본 요청을 변경하거나 원문 dump로 우회되지 않는다.

## M4 — 배포와 검증 기록

- [ ] T-401: Go compiler/Python/Node/Homebrew 없는 Mac에서 단일 arm64 바이너리를 실행한다. (AC-26)
- [ ] T-402: go test -race, parser/matcher/body fuzzing, govulncheck, 의존성·라이선스·checksum을 기록한다. (AC-25)
- [ ] T-403: metadata/JSON 두 모드에서 50 req/s와 1 GiB 전송, reload 병행 시 RSS/latency/loss를 측정한다.
- [ ] T-404: iPhone AirDrop 수동 전달·신뢰, 프록시 인증, 앱 재연결, Wi-Fi/sleep-wake, long-lived tunnel을 실기기로 검증한다.
- [ ] T-405: HTTP/2-only/Pinning/proxy 우회/WebSocket/SSE의 지원·미지원·미검증을 README에 분리한다.
- [ ] T-406: 외부 배포 시 서명/공증을 별도로 검증하고 38개 AC의 pass/fail/not-tested 표를 작성한다. 미검증을 통과로 표시하지 않는다.

## 구현 에이전트 시작 문구

> v0.3 명세와 이 체크리스트를 읽고 M0부터 구현한다. Go CLI, CA 없는 CONNECT 모니터링, config/.env 명시적 로드, 승인 기기, 안전한 종료를 먼저 완성한다. 이후 로컬 CA/경로 출력과 선택 도메인 MITM, 새 연결에만 적용되는 원자적 reload를 구현한다. CA 다운로드 서버·설치 기능·외부 CA·내장 CA fallback·Mac 키체인 변경·GUI/TUI·Pinning 우회는 추가하지 않는다. 구현 코드, 실제 실행한 테스트, 실기기 미검증을 구별해 기록한다.
