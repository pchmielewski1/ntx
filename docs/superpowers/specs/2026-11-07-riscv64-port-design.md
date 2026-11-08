# ntx — port na riscv64 (Linux, glibc) — design

Data: 2026-11-07 · Branch: `riscv64` (z `main`) · Status: **zatwierdzony, niezaimplementowany**

Dokumenty towarzyszące:
- plan wykonawczy: [`../plans/2026-11-07-riscv64-port.md`](../plans/2026-11-07-riscv64-port.md)
- środowisko lokalne (instalacja toolchainu i qemu, weryfikacja):
  [`../2026-11-07-riscv64-local-env.md`](../2026-11-07-riscv64-local-env.md)

## Intent i dlaczego

`ntx` ma dziś trzy architektury: x86_64 i aarch64 budowane i testowane automatycznie w
GitHub Actions (binarka + `.deb` + `.rpm` w każdym release) oraz mipsel (OpenWrt), którego
binarkę partner dokleja do release **ręcznie**, bo wymaga 3-gigabajtowego OpenWrt SDK.

Partner chce dodać **RISC-V** i nie chce powtarzać ręcznego kroku z mipsel. Jego pytanie
brzmiało: czy riscv da się budować w Actions automatycznie. Odpowiedź (sprawdzona spike'iem
2026-11-07, patrz niżej): **tak**. Toolchain i emulator są zwykłymi pakietami apt na
runnerze `ubuntu-22.04`, więc riscv64 może przejść tę samą bramę co x86_64/aarch64:
nic nie jest publikowane, dopóki testy nie przejdą.

Partner zażądał, by dokumentacja była wykonalna przez **lokalny model LLM** jako subagenta.
Dlatego plan zawiera dokładne komendy, oczekiwane wyjścia i warunki STOP. Pełne treści
krótkich skryptów (odstępstwo od zasady writing-plans „sygnatury zamiast ciał”) to **moja
decyzja** wynikająca z tego wymagania, zaakceptowana przez partnera po przeglądzie — patrz
„Decyzje autora”.

## Cel (target) — decyzje (moje; partner polecił zaczynać bez pytań)

- Architektura: **riscv64**, ABI **lp64d**, ISA **RV64GC** (domyślne dla
  `riscv64-linux-gnu-gcc` z Ubuntu). Pokrywa dystrybucje riscv64: Debian, Ubuntu, Fedora,
  Arch RISC-V, Alpine, Gentoo; płytki VisionFive 2, Milk-V, LicheePi 4A, SiFive.
- **glibc, linkowanie dynamiczne, PIE + pełne hardening flagi** — tak samo jak x86_64 i
  aarch64 (a nie static musl jak mipsel): riscv64 to dystrybucje ogólnego przeznaczenia z
  glibc, a dynamiczna binarka pozwala dać `.deb` jak dla pozostałych.
- Budowanie: **cross-kompilacja** na `ubuntu-22.04` (x86_64) + testy pod
  **`qemu-riscv64` user-mode**. Nie używamy pełnej emulacji systemu
  (`docker --platform linux/riscv64`): spike pokazał, że user-mode wystarcza i jest
  szybkie.
- Minimalna glibc na celu: **2.35** (cross-libc z Ubuntu 22.04; binarka realnie wymaga
  symboli do `GLIBC_2.34`).
- Rozszerzenia wektorowe (RVV), riscv32, musl/static riscv — poza zakresem.

## Rekonesans i spike (2026-11-07, host DGX Spark aarch64, kontenery Ubuntu)

Kod w `src/` jest endian-safe i nie rzutuje buforów na szersze typy (zero `(uint32_t *)`,
zero `#pragma pack`). riscv64 ma `__int128`, więc `src/crypto/ntx_x25519_fe.c:100`
wybiera szybką ścieżkę 128-bitową (tę samą co x86_64/aarch64); `src/crypto/ntx_aes.c:268`
widzi `__SIZEOF_SIZE_T__ == 8`.

Wyniki (spike niczego nie zmienił w repo):

| Sprawdzenie | Ubuntu 22.04 (CI) | Ubuntu 24.04 (lokalnie) |
|---|---|---|
| `riscv64-linux-gnu-gcc` | 11.4.0 | 13.3.0 |
| `qemu-riscv64` | 6.2.0 | 8.2.2 |
| `libc6-dev-riscv64-cross` | 2.35 | 2.39 |
| cały `src/` pod `-Werror` + hardening + `-pie` | OK, **bez zmian w kodzie** | OK |
| 117 × `test/t_*.c` kompilacja | OK | OK |
| 117 × `test/t_*.c` pod qemu | **117/117 PASS, 198 s** (najwolniejsze: `t_p256_kat` 29 s, `t_socks_udp` 20 s, `t_holepunch` 8 s; `NTX_TEST_TIMEOUT_SCALE=1`) | nie mierzone |
| `test/cli_errors.sh`, `test/net_loopback.sh`, `test/interop/ipc/interop_ipc.sh` przez wrapper qemu jako `./ntx` | PASS | — |
| `test/tls13_interop.sh` z cross-skompilowanym `tls_probe` przez wrapper | PASS | — |
| rozmiar `ntx-riscv64` | 299 120 B (strip: 240 856 B) | — |
| `objdump -p` NEEDED | `libc.so.6`, `ld-linux-riscv64-lp64d.so.1` | — |
| `file` | `ELF 64-bit LSB pie executable, UCB RISC-V, RVC, double-float ABI` | — |

Trzy pułapki znalezione w spike'u (każda ma zadanie w planie):
1. `make ntx CC=riscv64-linux-gnu-gcc` **nic nie buduje**, gdy istnieje natywny `./ntx`
   (cel plikowy „up to date”). riscv musi mieć osobny cel i osobną nazwę pliku.
2. `packaging/build-deb.sh` woła hostowy `strip`, który nie zna formatu RISC-V
   („Unable to recognise the format”), i bierze minimalną glibc z hosta (`getconf`).
3. Na hoście aarch64 obraz `ubuntu:*` z cache bywa amd64 → `exec format error`.
   Docker trzeba uruchamiać z jawnym `--platform`. Docker bez `--user` zostawia w repo pliki
   roota (tak powstał dzisiejszy `./ntx` należący do roota).

## Artefakty i nazwy (twarde — używane przez wszystkie zadania)

| Rzecz | Nazwa |
|---|---|
| binarka w katalogu repo | `./ntx-riscv64` (nigdy `./ntx`) |
| cel Makefile: build | `make riscv` (zawsze przebudowuje, wzór `make mips`) |
| cel: bramka rozmiaru | `make size-riscv` (< 1 048 576 B, **nie** zależy od `riscv`) |
| cel: unit testy pod qemu | `make test-riscv` |
| cel: testy shellowe pod qemu | `make test-riscv-shell` (**nie** zależy od `riscv`) |
| zmienne Makefile | `RISCV_CC ?= riscv64-linux-gnu-gcc` |
| tymczasowe binarki testów | `test/.riscv64.<nazwa>.tmp` |
| scratch testów shellowych | `test/.scratch/riscv64-shell/` |
| skrypty | `scripts/riscv/{qemu-user-run.sh,run-suite.sh,run-shell-suites.sh,docker-run.sh,Dockerfile}` |
| obraz docker lokalny | `ntx-riscv64-env:22.04` |
| asset release | `ntx-<ver>-linux-riscv64`, `ntx_<ver>_riscv64.deb` |
| job CI | `riscv64` w `ci.yml`, `build-riscv64` w `release.yml`, artefakt `dist-riscv64` |
| zmienne `build-deb.sh` | `NTX_STRIP` (domyślnie `strip`), `NTX_DEB_LIBC_MIN` (domyślnie `getconf`) |

Cele `size-riscv` i `test-riscv-shell` celowo nie zależą od `riscv`: `make riscv` zawsze
przebudowuje, więc zależność nadpisałaby binarkę z `NTX_VERSION` z release binarką z
domyślną wersją tuż przed pakowaniem.

## Cele / nie-cele / anty-cele

Cele:
1. `make riscv` → `./ntx-riscv64` (dynamiczny glibc, PIE, full RELRO, NX stack,
   stack protector, `_FORTIFY_SOURCE=2`), wersja z `NTX_VERSION`.
2. `make test-riscv`: wszystkie `test/t_*.c` zielone pod `qemu-riscv64`.
3. `make test-riscv-shell`: test-cli, test-net, test-ipc, test-tls13 zielone pod qemu
   (tls13: exit 77 = skip, jak natywnie).
4. CI (`ci.yml`) na każdym PR/push: job `riscv64` = build + size + oba zestawy testów.
5. Release (`release.yml`): job `build-riscv64` z tą samą bramą; `publish` czeka na niego;
   release zawiera `ntx-<ver>-linux-riscv64` i `ntx_<ver>_riscv64.deb`, oba w `SHA256SUMS`.
   **Zero ręcznych kroków** po publikacji.
6. Recepty źródłowe dopuszczają riscv64: Alpine `arch`, Arch `arch`, Gentoo `~riscv`,
   Nix `riscv64-linux`.
7. Lokalna powtarzalność: ten sam toolchain co CI dostępny przez
   `scripts/riscv/docker-run.sh` (Ubuntu 22.04 w dockerze), bez sudo.
8. Dokumentacja produktu zaktualizowana (README, testing, releasing, roadmap, packaging,
   architecture, CHANGELOG).

Nie-cele: `.rpm` riscv64 (Fedora riscv64 to architektura alternatywna; `build-rpm.sh`
odrzuca cross-arch i `rpmbuild` wymagałby `--target` + cross-strip — wpis w roadmap);
RVV/optymalizacje; riscv32; static musl riscv; testy na prawdziwej płytce (mile widziane,
nie są bramą); zmiany w kodzie C (spike nie wykazał potrzeby).

Anty-cele (porażka, nawet jeśli „działa”):
- nadpisanie lub przebudowanie natywnego `./ntx`, `.test.tmp`, `ntx-mipsel`;
- jakakolwiek zmiana zachowania mipsel (`scripts/mips/*`, cel `mips`, `test-mipsel`);
- modyfikacja istniejących skryptów testowych (`test/*.sh`, `test/interop/ipc/*`) — riscv
  dostaje własny harness;
- publikacja release bez zielonych testów riscv64;
- osłabianie asercji lub pomijanie testów pod qemu (jedyny dozwolony knob czasu:
  `NTX_TEST_TIMEOUT_SCALE`);
- `.deb` z `Depends: libc6 (>= X)` niższym niż glibc cross-libc, którą zbudowano binarkę;
- pliki roota w repo po lokalnym dockerze.

## Kryteria akceptacji

- Lokalnie (docker lub apt): `make riscv`, `make size-riscv`, `make test-riscv`
  (**3 zielone przebiegi z rzędu**, wzór portu mipsel), `make test-riscv-shell` — zielone.
- `md5sum ntx` przed i po całej pracy identyczne (lub `ntx` nie istnieje w obu chwilach).
- `make test` natywnie bez regresji (powinno być trywialne: brak zmian w C).
- `ci.yml` zielony na PR z gałęzi `riscv64` (wszystkie joby, w tym nowy `riscv64`).
- `release.yml` uruchomiony ręcznie (`workflow_dispatch`) na gałęzi `riscv64`: artefakt
  `dist-riscv64` zawiera dokładnie `ntx-<ver>-linux-riscv64` i `ntx_<ver>_riscv64.deb`;
  `dpkg-deb -I` pokazuje `Architecture: riscv64` i `Depends: libc6 (>= 2.35)`.
- Push do GitHuba i otwarcie PR wykonuje **człowiek albo agent po zgodzie partnera**.

## Decyzje autora (zaakceptowane przez partnera 2026-11-07)

1. Pełne treści skryptów i YAML w planie zamiast samych sygnatur (pod lokalny LLM).
2. glibc dynamicznie + `.deb`, zamiast static musl jak mipsel.
3. Cross + `qemu-user` na `ubuntu-22.04`, zamiast pełnej emulacji `docker --platform linux/riscv64`.
4. Brak `.rpm` riscv64 (wpis w roadmap).
5. Osobny harness `scripts/riscv/` zamiast uogólniania `scripts/mips/` (mipsel nie ma CI,
   więc jego regresji nie dałoby się wykryć automatycznie).
6. Recepty Alpine/Arch/Gentoo/Nix dopuszczają riscv64, mimo że nikt nie budował ich na
   prawdziwej dystrybucji riscv64.
7. Job riscv64 również w `ci.yml` (na każdym PR), nie tylko w `release.yml`.

## Zostawione budującemu

Dokładna treść opisów w dokumentacji produktu (w stylu istniejących plików); kolejność
kroków w obrębie zadania; czy `NTX_TEST_TIMEOUT_SCALE` w CI podnieść powyżej 1, jeśli
runner okaże się wolniejszy (tylko po zaobserwowanym timeoucie, wartość w commicie).
