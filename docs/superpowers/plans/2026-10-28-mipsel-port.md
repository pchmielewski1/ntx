# ntx mipsel Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Przenieś `ntx` na mipsel (OpenWrt `mipsel_24kc`-kompatybilnie): statyczna binarka `ntx-mipsel` w katalogu głównym repo + pełna suita unit zielona pod `qemu-mipsel`.

**Architecture:** Wszystko (cross-kompilacja, QEMU) dzieje się na **laptopie x86_64**; repo jest zamontowane sshfs z dgx-spark w `/home/user/vsc/nanotorrent` i Spark pełni **wyłącznie** rolę udziału sieciowego z danymi — żadnych buildów na Sparku. Cross-toolchain Bootlin musl/soft, testy unit kompilowane cross i odpalane przez `qemu-mipsel` (TCG, user-mode), e2e best-effort na `qemu-system-mips` malta z OpenWrt. Wszystkie artefakty cross mają własne nazwy — istniejące binarki aarch64 pozostają nietknięte.

**Tech Stack:** Bootlin `mips32el` musl soft (host x86_64), qemu użytkownika/systemu bez sudo (dpkg -x deba do `~/.local/`, fallback docker), GNU Make, OpenWrt malta LE 23.05.x, bash.

**Spec:** `docs/superpowers/specs/2026-10-28-mipsel-port-design.md`

## Global Constraints

- Praca w `/home/user/vsc/nanotorrent` (sshfs z dgx-spark). **QEMU i wszystkie buildy na laptopie (x86_64)**; na Sparku nie odpalamy nic poza git (operacje git przez sshfs są OK, tak działał cały projekt).
- **Nowy kod nie może psuć działającego programu na innych architekturach:** nigdy nie nadpisywać `ntx` (aarch64), `.test.tmp`, `trk_http_probe` — artefakty cross wyłącznie `ntx-mipsel`, `build-mipsel/`, `test/.mipsel*.tmp`; natywne kontrole tylko out-of-tree do `test/.agent-work/`.
- QEMU: przed każdym startem `qemu-system-mips` — `pgrep -f qemu-system-mips` (jeśli żyje obca instancja: STOP, nie dubluj) + mkdir-lock `test/.scratch/malta.lock`, `trap` sprzątający przy exit; jedna instancja, testy seriami w jednym bootu. Dotyczy też laptopa (użytkownik może mieć swoje QEMU).
- Toolchain, deb-y qemu i obrazy OpenWrt **poza repo**: `~/toolchains/` na laptopie; scratch tylko `test/.scratch/` / `test/.agent-work/` (nie `/tmp`).
- Dysk laptopa bywa pełny: skrypt provisioning wymaga ≥3G wolnego na `/` przed pobraniem (guard `df`).
- Binarka dowodowa: `ntx-mipsel` w katalogu głównym repo, statyczna, soft-float o32.
- Suita unit pod qemu: **3 pełne zielone przebiegi z rzędu**; brak pomijanych testów; osłabione asercje zabronione; przed i po całym projekcie `md5sum ntx` musi być identyczne (dowód nietkniętości aarch64).

## Review Focus

- Nie wyrównane odczyty po rzutach — parser jest byte'owy, ale każdy nowy kod cross-fixowany nie może wprowadzić `(u32_t*)buf`; spodziewany objaw: SIGBUS/fixupy pod TCG.
- Formatowanie `double` pod soft-float (`%.1fM/s` w UI) — wynik identyczny jak na natywnym dla tych samych danych.
- `epoll_create1/ctl/wait` pod musl+TCG — netx musi normalnie tickać (objaw błędu: wiszące testy net/dial).
- Wire-format BE na LE mipsel — wektory golden (announce/dht/pe/tls) przechodzą bez zmian bajtów.
- Flakiness timingów pod TCG — testy timingowe tylko przez mnożnik `NTX_TEST_TIMEOUT_SCALE`, nigdy przez luzowanie asercji.
- Regresja natywna: każda poprawka portability musl musi przechodzić kontrolę natywną gcc x86_64 out-of-tree w tym samym taskie.

---

### Task 1: Provisioning toolchainu Bootlin na laptopie

**Files:**
- Create: `scripts/mips/provision-toolchain.sh`
- Modify: `.gitignore` (dopisać `build-mipsel/`, `test/.mipsel*.tmp`)

**Interfaces:**
- Consumes: —
- Produces: `~/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc` na laptopie (skrypt idempotentny; powtórny run = no-op).

- [ ] **Step 1: Znajdź dokładny URL tarballa Bootlin `mips32el`, musl, soft, host x86_64**

Run: `curl -s https://toolchains.bootlin.com/downloads/releases/toolchains/mips32el/tarballs/ | grep -o 'mips32el[^"<>]*musl[^"<>]*soft[^"<>]*x86-64\.tar\.xz' | sort -u`
Expected: ≥1 nazwa (wybierz najnowszy stable). Fallback tylko gdy brak: crosstool-ng w dockerze (odnotuj decyzję w commicie).

- [ ] **Step 2: Napisz `scripts/mips/provision-toolchain.sh`**

`set -euo pipefail`. Guard: `df -P / | awk 'NR==2{print $4}'` ≥ 3 GB, inaczej exit 1 z komunikatem. Jeśli `~/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc` istnieje → exit 0; inaczej pobierz URL (stała na górze skryptu) do `~/toolchains/`, rozpakuj, znormalizuj nazwę katalogu docelowego.

- [ ] **Step 3: Uruchom i skompiluj hello-world**

Run:
```bash
bash scripts/mips/provision-toolchain.sh && mkdir -p test/.scratch && echo "int main(){return 42;}" > test/.scratch/h.c && ~/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc -static -o test/.scratch/h test/.scratch/h.c && file test/.scratch/h
```
Expected: `ELF 32-bit LSB executable, MIPS, MIPS32 ... statically linked`.

- [ ] **Step 4: Zweryfikuj soft-float**

Run: `readelf -A test/.scratch/h | grep -i "fp_abi\|float"`
Expected: soft-float (`Tag_ABI_FP_...` bez hard); odnotuj wynik w commicie.

- [ ] **Step 5: Commit**

```bash
git add scripts/mips/provision-toolchain.sh .gitignore
git commit -m "build(mips): toolchain provisioning script (bootlin mips32el musl soft, host x86_64)"
```

### Task 2: qemu-mipsel user-mode na hoście (bez sudo)

**Files:**
- Create: `scripts/mips/qemu-user-run.sh`

**Interfaces:**
- Consumes: statyczne binarki mipsel pod repo
- Produces: `scripts/mips/qemu-user-run.sh <ścieżka-względem-repo> [args...]` → uruchamia pod `qemu-mipsel`, propaguje exit code; binarka qemu: `~/toolchains/qemu/bin/qemu-mipsel-static` (albo systemowa, jeśli się pojawi).

- [ ] **Step 1: Pozyskaj qemu-mipsel bez sudo (priorytet: deb, fallback: docker)**

```bash
mkdir -p ~/toolchains/qemu-deb && cd ~/toolchains/qemu-deb
apt-get download qemu-user-static && dpkg -x qemu-user-static_*.deb ~/toolchains/qemu
```
Expected: `~/toolchains/qemu/usr/bin/qemu-mipsel-static` działa (`--version`). Fallback: obraz `FROM ubuntu:24.04` + `apt-get install qemu-user-static`, uruchamianie przez `docker run --rm -v "$PWD:/repo" ntx-qemu:mipsel ...` (wtedy `qemu-user-run.sh` wybiera ścieżkę automatycznie).

- [ ] **Step 2: Napisz `scripts/mips/qemu-user-run.sh`**

`QEMU_BIN` autodetekcja (`~/toolchains/qemu/usr/bin/qemu-mipsel-static` → docker fallback); `exec "$QEMU_BIN" -0 ntx "$PWD/$1" "${@:2}"`; propagacja exit code.

- [ ] **Step 3: Smoke: hello z Task 1 zwraca 42**

Run: `bash scripts/mips/qemu-user-run.sh test/.scratch/h; echo RC=$?`
Expected: `RC=42`.

- [ ] **Step 4: Commit**

```bash
git add scripts/mips/qemu-user-run.sh
git commit -m "build(mips): qemu-mipsel user-mode runner (sudo-less deb extract, docker fallback)"
```

### Task 3: Cel `make mips` → `ntx-mipsel` w katalogu głównym

**Files:**
- Modify: `Makefile` (nowe zmienne + cel; istniejące cele nietknięte)

**Interfaces:**
- Consumes: toolchain z Task 1
- Produces: `make mips` → `./ntx-mipsel` (statyczny, soft-float); `MIPS_CC` nadpisywalny; `clean` sprząta `ntx-mipsel`.

- [ ] **Step 1: Dodaj do Makefile**

```make
MIPS_CC ?= $(HOME)/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc
mips: $(SRCS) ; $(MIPS_CC) $(CFLAGS) -static $(VERSION_DEFINE) -o ntx-mipsel $(SRCS) $(LDFLAGS) $(LDLIBS)
```
PIE/RELRO odpuszczone dla `-static` musl (precedens: cel `static`); `mips` do `.PHONY` NIE trafia (plik-cel); `clean` += `ntx-mipsel`.

- [ ] **Step 2: Zbuduj i sprawdź dowód**

Run: `make mips && file ntx-mipsel && ls -l ntx-mipsel && readelf -A ntx-mipsel | grep -i float`
Expected: `ELF 32-bit ... MIPS, MIPS32 ... statically linked`, soft-float; rozmiar odnotowany w raporcie (nie gate).

- [ ] **Step 3: Smoke pod qemu**

Sprawdź w `src/ui/ntx_cli.c` bezpieczne wywołanie bez sieci (usage/`--version`) i odpal:
`bash scripts/mips/qemu-user-run.sh ntx-mipsel <ten-arg>; echo RC=$?`
Expected: RC=0, znany output.

- [ ] **Step 4: Nietkniętość aarch64**

`stat -c '%Y %s' ntx` przed/po `make mips` identyczne; `git status --porcelain` nie pokazuje zmian w ścieżkach buildów natywnych.

- [ ] **Step 5: Commit**

```bash
git add Makefile
git commit -m "build(mips): make mips target producing static ntx-mipsel at repo root"
```

### Task 4: Suita unit pod qemu-mipsel (`make test-mipsel`)

**Files:**
- Modify: `Makefile` (cel `test-mipsel`, `.PHONY`)
- Create: `scripts/mips/run-suite.sh`

**Interfaces:**
- Consumes: `MIPS_CC` (Task 3), `scripts/mips/qemu-user-run.sh` (Task 2)
- Produces: `make test-mipsel` — wszystkie `test/t_*.c` skompilowane cross (do `test/.mipsel.<nazwa>.tmp`) i odpalone pod qemu; FAIL → lista + exit 1; zielono → `ALL PASS` + exit 0.

- [ ] **Step 1: Napisz `scripts/mips/run-suite.sh`**

Pętla po `test/t_*.c`: `$(MIPS_CC) $(CFLAGS) -o test/.mipsel.<base>.tmp $f $(LDLIBS)` (identyczne flagi jak `make test`), potem `bash scripts/mips/qemu-user-run.sh <bin>`; kumuluj nazwy faili, wypisz na końcu; sprzątaj `.tmp`; propaguj `NTX_TEST_TIMEOUT_SCALE` do środowiska qemu.

- [ ] **Step 2: Pierwszy przebieg — napraw błędy kompilacji musl/-Werror**

Run: `bash scripts/mips/run-suite.sh 2>&1 | tail -40`
Poprawki portability w `src/`/`test/` z zachowaniem semantyki natywnej; **każdą zmianę w src/ potwierdź natywnie**: kompilacja out-of-tree gcc x86_64 do `test/.agent-work/native-check/` (Review Focus).

- [ ] **Step 3: Dodaj cel `test-mipsel` do Makefile**

`test-mipsel: ; @bash scripts/mips/run-suite.sh` + `.PHONY`.

- [ ] **Step 4: Przebieg do zielonego (poza timingami)**

Run: `make test-mipsel`
Expected: `ALL PASS` (timingowe mogą wisać — Task 5).

- [ ] **Step 5: Commit**

```bash
git add Makefile scripts/mips/run-suite.sh
git commit -m "test(mips): cross-compiled unit suite under qemu-mipsel"
```

### Task 5: Mnożnik timeoutów i 3× zielona suita

**Files:**
- Create: `test/tscale.h`
- Create: `test/t_tscale.c`
- Modify: testy timingowe, które realnie padły pod TCG (kandydaci: `t_dial_backoff.c`, `t_http_proxy_slow.c`, `t_dht_lookup.c`, `t_hash_exchange.c`, `t_netx_route.c`)

**Interfaces:**
- Consumes: env `NTX_TEST_TIMEOUT_SCALE`
- Produces: `long ts_ms(long base_ms)` w `test/tscale.h` — `base_ms * scale`, scale z env parsowany raz, śmieci/brak → 1.

- [ ] **Step 1: `test/tscale.h` + test helpera (TDD)**

`test/t_tscale.c`: przy `NTX_TEST_TIMEOUT_SCALE=5` → `ts_ms(100)==500`; brak env → `ts_ms(100)==100`; env=`abc` → `ts_ms(100)==100`. Helper neutralny: natywny przebieg testu też musi przechodzić.

- [ ] **Step 2: Zastosuj mnożnik TYLKO w testach, które padły pod TCG**

Spania/waits/okna czasowe → `ts_ms(...)`; asercje bez zmian. Listę zmienionych plików w commicie.

- [ ] **Step 3: Dobierz skalę i wymuś 3× zielone z rzędu**

Dla skal rosnąco (start 3): jeden przebieg; gdy suita zielona — 3 następujące pełne przebiegi pod tę samą skalę.
Expected: `ALL PASS` ×3; skala w wiadomości commita.

- [ ] **Step 4: Kontrola natywna helpera i ruszonych testów**

Kompilacja+i run zmienionych `test/t_*.c` natywnym gcc out-of-tree (`test/.agent-work/native-check/`), bez `NTX_TEST_TIMEOUT_SCALE`.
Expected: przechodzą jak wcześniej.

- [ ] **Step 5: Commit**

```bash
git add test/tscale.h test/t_tscale.c test/<zmienione>.c
git commit -m "test(mips): TCG timeout scaling, 3x green qemu-mipsel suite (scale=N)"
```

### Task 6: Regresja natywna + dowód nietkniętości aarch64

**Files:**
- Create: `scripts/mips/native-check.sh`

**Interfaces:**
- Consumes: całość zmian Task 1–5; baseline md5 `ntx` (aarch64)
- Produces: `scripts/mips/native-check.sh` — out-of-tree kompilacja WSZYSTKICH `src/*.c` (jako jeden program + per-file `-fsyntax-only`) i WSZYSTKICH `test/t_*.c` natywnym gcc do `test/.agent-work/native-check/`, odpala testy tam; exit 0 = zielono. Nigdy nie pisze `.test.tmp`/`ntx` w korzeniu.

- [ ] **Step 1: Zapisz baseline md5 aarch64**

`md5sum ntx > test/.scratch/ntx-aarch64.md5` (plik poza ścieżkami buildu).

- [ ] **Step 2: Napisz i odpal `scripts/mips/native-check.sh`**

Expected: `ALL PASS`; binarki/obiekty wyłącznie w `test/.agent-work/native-check/`.

- [ ] **Step 3: Dowód nietkniętości**

`md5sum -c test/.scratch/ntx-aarch64.md5` → OK (aarch64 `ntx` niezmieniony od początku portu).

- [ ] **Step 4: Commit**

```bash
git add scripts/mips/native-check.sh
git commit -m "test(mips): out-of-tree native regression harness + aarch64 integrity proof"
```

### Task 7 (best-effort): e2e na malta z OpenWrt

**Files:**
- Create: `scripts/mips/malta-boot.sh`

**Interfaces:**
- Consumes: `ntx-mipsel` (Task 3)
- Produces: `malta-boot.sh` (lock + check obcej instancji PRZED czymkolwiek); udokumentowany przebieg: `ntx-mipsel` w goscu OpenWrt malta LE ściąga mały torrent od seedera na hoście (user-net, gateway `10.0.2.2`), sha256 OK.

- [ ] **Step 1: Lock i check instancji na starcie skryptu**

`pgrep -f qemu-system-mips` → żyje = STOP z komunikatem (nie dubluj!); `mkdir test/.scratch/malta.lock || STOP`; `trap 'rmdir ...; kill $QPID' EXIT`; PID qemu zapisany w lockdirze; zabijanie wyłącznie własnego PID.

- [ ] **Step 2: Pozyskaj qemu-system-mips bez sudo + obrazy OpenWrt malta LE**

`apt-get download qemu-system-mips libfdt1 ...; dpkg -x` do `~/toolchains/qemu` (lista zależności wg potrzeb; fallback docker `ubuntu:24.04` + `qemu-system-mips`). Obrazy: `openwrt-*-malta-le-generic-kernel.bin` + `...-squashfs-cpio.bin` (wersję wybiera budujący, np. 23.05.x) → `test/.scratch/malta/`.

- [ ] **Step 3: Boot i dostęp do gosca**

`qemu-system-mips -M malta -kernel <kernel> -initrd <cpio> -nographic -net user,hostfwd=tcp::2222-:22 -net nic`; log bootu do `test/.scratch/malta/boot.log`; `ssh -p 2222 root@127.0.0.1`.

- [ ] **Step 4: Torrent przez guest**

`scp ntx-mipsel` do gosca; seeder na hoście (python http.server + lokalny tracker, albo `ntx`-seed — najprostsze działające); w goscu `./ntx-mipsel <magnet>`; weryfikacja sha256.
Expected: plik zgodny; output do `docs/superpowers/` jako dowód best-effort.

- [ ] **Step 5: Sprzątnięcie + commit**

Zabij tylko swój PID qemu, usuń lockdir.
```bash
git add scripts/mips/
git commit -m "test(mips): malta e2e boot scripts (best-effort torrent smoke)"
```
