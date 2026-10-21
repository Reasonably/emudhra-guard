# emudhra-guard

[English](README.md) | [한국어](README.ko.md)

업데이트를 적용하기 어렵거나 명시적인 로컬 차단이 필요한 환경을 위한 보조 도구입니다. macOS와 Windows에서 eMudhra/emSign 인증서 23개의 로컬 차단 상태를 확인하고, 명시적으로 신뢰를 거부합니다. 추가 런타임이나 인터넷 연결 없이 운영체제에 포함된 기능만 사용합니다.

## 업데이트를 먼저 적용하세요

**수동 차단에 앞서 이번 사고 대응이 포함된 공식 업데이트를 먼저 적용하는 것을 권장합니다.** 애플리케이션이 TLS 인증서 검증에 실제로 사용하는 운영체제, 브라우저, CA 번들 또는 런타임을 업데이트하세요. 설치한 버전에 대응 조치가 포함됐는지 확인하고, 필요한 경우 애플리케이션을 재시작하거나 재배포해 갱신된 신뢰 데이터를 사용하도록 하세요.

업데이트로 이미 문제 인증서를 거부하고 있다면 별도 수동 차단을 적용할 필요는 없습니다. 특정 CA 번들을 업데이트하면 그 번들을 사용하는 애플리케이션에 적용되며, 기기의 모든 인증서 저장소가 함께 갱신되지는 않습니다.

이 도구는 업데이트를 신속히 적용하기 어렵거나 운영 환경에서 명시적인 로컬 신뢰 거부가 필요할 때 보조 수단으로 사용하세요. 공급업체의 대응 조치가 설치됐는지가 아니라 수동 차단 설정을 확인하므로, `NOT_CONFIGURED` 결과가 애플리케이션의 취약성을 의미하지는 않습니다.

## 수동 차단 방식

기본 실행은 조회만 합니다. 인증서를 단순히 삭제하면 서버의 중간 인증서 재전송이나 루트 저장소 업데이트로 신뢰가 다시 생길 수 있으므로, 차단할 때는 macOS의 `deny` 또는 Windows의 `Disallowed` 저장소를 사용합니다.

## 대상과 지원 범위

2026-10-21에 확인한 고정 목록입니다.

- emSign 루트 7개: `Root CA G1/C1`, `ECC Root CA G3/C3`, `Root TLS CA G1/G3`, `Root CS CA G3`입니다.
- 사고에 관련된 중간 인증서 8개와 같은 키를 사용하는 교차서명본 8개입니다.
- 확인 기준은 이름 검색이 아닌 인증서 DER의 SHA-256 지문입니다. 데이터 파일 자체의 SHA-256도 두 스크립트에 고정되어 있습니다.

루트 7개를 차단하는 것은 이 도구의 차단 범위입니다. 그 루트의 개인 키가 모두 유출됐다는 뜻은 아닙니다. 이 목록은 새로운 인증서를 자동 탐지하거나 최신 폐기 목록을 대신하지 않습니다.

| 운영체제 | 방식 | 적용 대상 |
| --- | --- | --- |
| macOS | 기본 키체인과 사용자 신뢰 설정, 또는 System 키체인과 관리자 신뢰 설정에 `deny`를 기록합니다. | OS 신뢰 설정을 사용하는 앱, Safari, 로컬 인증서를 사용하는 Chrome·Edge·Chromium 계열입니다. |
| Windows | `CurrentUser` 또는 `LocalMachine`의 `Disallowed` 저장소에 추가합니다. | Windows 신뢰 저장소를 사용하는 앱과 Chrome·Edge입니다. |

Firefox/NSS, Java, Python의 별도 CA 번들, 컨테이너 내부 저장소는 수정하지 않습니다. 브라우저 정책에서 OS의 로컬 인증서를 사용하지 않도록 설정했다면 해당 브라우저에도 별도 조치가 필요합니다. 차단 후에는 브라우저를 다시 시작하세요. 시스템 범위 설정도 다른 사용자나 관리 정책의 명시적 설정까지 검사하는 기능은 아닙니다.

## macOS

macOS에 기본으로 포함된 Bash, `security`, `openssl`, `plutil`을 사용합니다.

```bash
git clone https://github.com/Reasonably/emudhra-guard.git "$HOME/workspace/emudhra-guard"

# 현재 계정의 차단 상태를 조회합니다. 인수가 없을 때도 조회만 합니다.
bash "$HOME/workspace/emudhra-guard/macos.sh" check

# 현재 계정에서 차단합니다. macOS가 인증을 요청할 수 있습니다.
bash "$HOME/workspace/emudhra-guard/macos.sh" block

# 시스템 범위의 차단 상태를 조회합니다.
bash "$HOME/workspace/emudhra-guard/macos.sh" check --system

# 시스템 범위에 적용하려면 관리자 권한이 필요합니다.
sudo bash "$HOME/workspace/emudhra-guard/macos.sh" block --system
```

백업은 사용자 범위에서 `~/Library/Application Support/emudhra-guard/backups/`, 시스템 범위에서 `/var/root/Library/Application Support/emudhra-guard/backups/`에 저장됩니다. 실행 결과에 정확한 경로가 표시됩니다.

```bash
# BACKUP_DIRECTORY를 실행 결과에 표시된 실제 절대 경로로 바꿉니다.
bash "$HOME/workspace/emudhra-guard/macos.sh" restore /absolute/path/to/BACKUP_DIRECTORY

# 시스템 범위 백업 복원입니다.
sudo bash "$HOME/workspace/emudhra-guard/macos.sh" restore /var/root/Library/Application\ Support/emudhra-guard/backups/BACKUP_DIRECTORY
```

복원은 해당 실행에서 바꾼 신뢰 항목만 되돌립니다. 다른 인증서에 나중에 추가한 설정은 유지하며, 차단 대상의 설정을 별도로 바꿨다면 덮어쓰지 않고 중단합니다. 키체인에 추가한 공개 인증서 사본은 남기고 신뢰 설정만 복원합니다.

## Windows

Windows PowerShell 5.1 이상을 사용합니다. 저장소를 복제하거나 배포 ZIP을 풀 때 `windows.ps1` 옆의 `data` 폴더도 함께 두세요.

```powershell
git clone https://github.com/Reasonably/emudhra-guard.git "$HOME\emudhra-guard"

# 현재 계정의 차단 상태를 조회합니다.
& "$HOME\emudhra-guard\windows.ps1" -Action Check

# 현재 계정에서 차단합니다.
& "$HOME\emudhra-guard\windows.ps1" -Action Block

# 시스템 범위를 조회합니다.
& "$HOME\emudhra-guard\windows.ps1" -Action Check -Scope LocalMachine

# 아래 명령은 관리자 권한 PowerShell에서 실행합니다.
& "$HOME\emudhra-guard\windows.ps1" -Action Block -Scope LocalMachine

# 실행 결과에 표시된 실제 백업 파일 경로를 사용합니다.
& "$HOME\emudhra-guard\windows.ps1" -Action Restore -BackupPath 'C:\absolute\path\to\backup.json'
```

실행 정책이 스크립트를 막으면 조직의 승인 절차에 따라 실행하세요. 이 도구는 실행 정책을 변경하지 않습니다.

백업은 사용자 범위에서 `%LOCALAPPDATA%\emudhra-guard\backups`, 시스템 범위에서 `%ProgramData%\emudhra-guard\backups`에 저장됩니다. 복원할 때는 백업에 기록된 범위를 사용하고, 이 실행에서 새로 추가한 차단 항목만 제거합니다. 원래 있던 차단 항목은 유지합니다.

## 결과 해석과 복구

- `DENY`: 선택한 범위에 명시적 차단이 있습니다. macOS에서는 브라우저가 읽을 공개 인증서 사본도 확인합니다.
- `DENY_WITHOUT_LOCAL_COPY`: macOS 신뢰 거부는 있으나 선택한 키체인에 인증서 사본이 없습니다. `block`으로 보완할 수 있습니다.
- `NOT_CONFIGURED`: 이 도구가 확인하는 범위에 명시적 차단이 없습니다. 브라우저 자체의 폐기 목록 등으로 이미 보호되고 있을 수 있으므로, 취약하다는 판정은 아닙니다.
- 종료 코드 `0`은 조회 시 23개 모두 차단됐거나 요청이 완료됐다는 뜻입니다. `2`는 조회 결과에 미설정 항목이 있다는 뜻이고, `1`은 오류입니다.

변경 전에 백업을 먼저 저장합니다. 인증이 취소되거나 도중에 실패하면 성공으로 표시하지 않으며, 출력된 백업을 사용해 복원할 수 있습니다. 동시에 다른 도구로 같은 인증서의 신뢰 설정을 바꾸지 마세요. macOS는 가져오기 직전에 전체 신뢰 설정의 변경도 검사하지만, 검사와 OS 변경 사이의 원자적 잠금까지 제공하지는 않습니다.

복원하면 해당 인증서가 다시 기본 신뢰 상태로 돌아갈 수 있습니다. 정상 웹사이트나 코드 서명도 차단 범위에 포함되므로, 필요한 경우에만 복원하세요. 로컬 백업에는 호스트나 키체인 관련 정보가 있을 수 있으며 공개 저장소에 올리지 마세요.

## 근거와 검증

- [Mozilla의 사고 기록](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [emSign 공식 인증서 저장소](https://repository.emsign.com/)
- [교차서명 인증서 공개 자료](https://github.com/Fluepke/emudrahahahahaha)
- [Chromium의 OS 신뢰 설정 처리](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md)
- [Microsoft X509Store 문서](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store)

개별 지문과 출처는 [data/provenance.json](data/provenance.json)에 있습니다. 개인 키는 포함하지 않습니다.

검증은 데이터 지문 일치, 조회의 무변경성, 반복 실행, 기존 설정 보존, 선택적 복원, 변조된 입력 거부를 다룹니다. macOS 테스트는 OS의 오프라인 plist 생성 기능과 모의 저장소를 사용하고, Windows 테스트는 임시 사용자 인증서 저장소를 사용합니다. 실제 신뢰 저장소를 변경하는 테스트는 자동 실행하지 않습니다.

## 라이선스

코드는 [MIT](LICENSE) 라이선스입니다. 인증서 데이터의 원본과 지문은 출처 목록에 기록했습니다. 배포 ZIP에도 코드와 공개 인증서 데이터만 포함합니다.
