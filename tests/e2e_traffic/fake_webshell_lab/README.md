# Fake JSP Webshell Lab (E2E only)

DSP Traffic Regression E2E용 **가짜** `shell.jsp` 호환 HTTP 서버이다.

## 목적

- 실제 침투/공격 성공 검증용이 **아니다**.
- DSP **webshell provider**의 command-only execution path와 traffic generation을 검증한다.
- `10.10.10.50` 등 실 webshell host가 비가용일 때 lab에서 webshell E2E를 계속한다.

## DSP JSP contract

DSP JSP provider (`JspCommandEncoder.COMMAND_PARAM`)는 다음을 사용한다.

| Method | Parameter | Example |
| ------ | --------- | ------- |
| GET | `cmd` | `GET /shell.jsp?cmd=whoami` |
| POST | `cmd` (form-urlencoded) | `POST /shell.jsp` body `cmd=whoami` |

이 fake server는 호환을 위해 `cmd` / `command` / `c`를 모두 받는다.
응답 끝에 DSP가 strip하는 `__EXIT_CODE:<n>` 마커를 붙인다.

## 실행

```bash
cd /home/aella/xdr-poc-script

./tests/e2e_traffic/fake_webshell_lab/start_fake_shell.sh 0.0.0.0 8080
```

출력 예:

```
FAKE_SHELL_URL=http://127.0.0.1:8080/shell.jsp
FAKE_SHELL_LAB_URL=http://10.10.10.1:8080/shell.jsp
FAKE_SHELL_PID=...
FAKE_SHELL_LOG=/tmp/fake_shelljsp_lab.log
```

기본:

- bind: `0.0.0.0:8080`
- pid: `/tmp/fake_shelljsp_lab.pid`
- log: `/tmp/fake_shelljsp_lab.log`

## 중지

```bash
./tests/e2e_traffic/fake_webshell_lab/stop_fake_shell.sh
```

## 테스트

```bash
./tests/e2e_traffic/fake_webshell_lab/test_fake_shell.sh http://127.0.0.1:8080/shell.jsp

# lab IP로도 확인 (br0에 10.10.10.1이 있을 때)
curl "http://10.10.10.1:8080/shell.jsp?cmd=whoami"
```

## webshell E2E 예시

tcpdump 권한과 capture interface를 먼저 확인한다.

```bash
getcap "$(command -v tcpdump)"
tcpdump -i br0 -nn -c 5 'tcp or udp or icmp'
```

fake shell 기동 후:

```bash
./tests/e2e_traffic/fake_webshell_lab/start_fake_shell.sh 0.0.0.0 8080
./tests/e2e_traffic/fake_webshell_lab/test_fake_shell.sh http://127.0.0.1:8080/shell.jsp

./tests/e2e_traffic/run_e2e_traffic.sh \
  --provider webshell \
  --profile normal \
  --target-net 10.10.10.0/24 \
  --interface br0 \
  --webshell-type jsp \
  --webshell-url http://127.0.0.1:8080/shell.jsp \
  --output-dir /tmp/dsp-e2e/webshell-jsp-normal
```

lab IP URL:

```bash
./tests/e2e_traffic/run_e2e_traffic.sh \
  --provider webshell \
  --profile normal \
  --target-net 10.10.10.0/24 \
  --interface br0 \
  --webshell-type jsp \
  --webshell-url http://10.10.10.1:8080/shell.jsp \
  --output-dir /tmp/dsp-e2e/webshell-jsp-normal
```

## 주의 사항

- 외부 공개 금지. lab bind만 사용한다.
- command execution은 **테스트 환경 전용**이다.
- fake webshell이 DSP와 **같은 머신**에서 돌면 local provider와 **source IP가 같을 수 있다**.
  - 이 경우 origin parity는 제한적으로만 해석한다.
  - 정확한 origin 검증은 별도 lab VM / container namespace에서 fake shell을 실행해야 한다.
- DSP runtime / Scenario Runner / Planner / `manifest.json` / `run_scenario.py` / `remote_discovery.py`를 webshell host에 배포하지 않는다 (command-only).
- multipart upload는 의도적으로 거부한다 (command-only 검증).

## 파일

| 파일 | 역할 |
| ---- | ---- |
| `fake_shell_server.py` | HTTP `/shell.jsp` command executor |
| `start_fake_shell.sh` | 백그라운드 기동 |
| `stop_fake_shell.sh` | 종료 |
| `test_fake_shell.sh` | curl smoke test |
