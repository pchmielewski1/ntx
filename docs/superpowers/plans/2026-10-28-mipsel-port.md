# ntx mipsel Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Przenieś `ntx` na mipsel (OpenWrt `mipsel_24kc`-kompatybilnie): statyczna binarka `ntx-mipsel` w katalogu głównym repo + pełna suita unit zielona pod `qemu-mipsel`.

**Architecture:** Cross-kompilacja na dgx-spark (aarch64) toolchainem Bootlin musl/soft; testy unit kompilowane cross i odpalane przez `qemu-mipsel` w dockerze (TCG, user-mode); e2e best-effort na `qemu-system-mips` malta z OpenWrt. Wszystkie artefakty cross w osobnych ścieżkach — binarki aarch64 (`ntx`, `.test.tmp`) nietknięte.

**Tech Stack:** Bootlin `mips32el` musl soft toolchain, docker (qemu-user-static, qemu-system-mips), GNU Make, OpenWrt malta LE 23.05.x, bash.

**Spec:** `docs/superpowers/specs/2026-10-28-mipsel-port-design.md`

## Global Constraints

- Wszystkie buildy/QEMU **tylko na dgx-spark** przez `ssh dgx-spark 'cd ~/nanotorrent && ...'` (repo zamontowane sshfs w `/home/user/vsc/nanotorrent`; po stronie lokalnej **nigdy** `make`).
- Nigdy nie nadpisywać: `ntx`, `.test.tmp`, obiektów aarch64. Artefakty cross: `ntx-mipsel`, `build-mipsel/`.
- QEMU: przed każdym startem `qemu-system-mips` — sprawdzenie działającej instancji (`pgrep -f qemu-system-mips`) + mkdir-lock `test/.scratch/malta.lock`; jedna instancja; testy seriami w jednym bootu.
- Toolchain i obrazy docker poza repo (`~/toolchains/`, obrazy dockera); scratch tylko pod `test/.scratch/` lub `test/.agent-work/` (nie `/tmp`).
- Binarka dowodowa: `/ntx-mipsel` w katalogu głównym repo, statyczna, soft-float o32.
- Suita unit pod qemu: **3 pełne zielone przebiegi z rzędu**; brak pomijanych testów; osłabione asercje zabronione.

## Review Focus

- Nie wyrównane odczyty po rzutach — parser jest byte'owy, ale każdy nowy kod cross-fixowany nie może wprowadzić `(u32_t*)buf`; spodziewany objaw: SIGBUS/fixupy pod TCG.
- Formatowanie `double` pod soft-float (`%.1fM/s` w UI) — wynik musi być identyczny jak na aarch64 dla tych samych danych.
- `epoll_create1/ctl/wait` pod musl+TCG — netx musi normalnie tickać (objaw błędu: wiszące testy net/dial).
- Wire-format BE na LE mipsel — wektory golden (announce/dht/pe/tls) muszą przejść bez zmian bajtów.
- Flakiness timingów pod TCG — testy timingowe tylko przez mnożnik `NTX_TEST_TIMEOUT_SCALE`, nigdy przez luzowanie asercji.

---

### Task 1: Provisioning toolchainu Bootlin na Sparku

**Files:**
- Create: `scripts/mips/provision-toolchain.sh`
- Modify: `.gitignore` (dopisać `build-mipsel/`, `test/.mipsel*.tmp`)

**Interfaces:**
- Consumes: —
- Produces: `~/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc` na Sparku (idempotentny skrypt; powtarzalny run = no-op).

- [ ] **Step 1: Zbadaj dostępność host-aarch64 dla Bootlin `mips32el` musl soft**

Run: `ssh dgx-spark 'curl -sI https://toolchains.bootlin.com/downloads/releases/toolchains/mips32el/tarballs/ | head -1'` i lista tarballi (`curl -s <index> | grep -o "mips32el[^\"<>]*musl[^\"<>]*aarch64[^\"<>]*\.tar\.xz"`). Jeśli brak buildu aarch64 → fallback (decyzja budującego): kontener x86_64 z binfmt albo crosstool-ng; odnotuj wybór w commicie.

- [ ] **Step 2: Napisz `scripts/mips/provision-toolchain.sh`**

Skrypt: jeśli `~/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc` istnieje → exit 0; inaczej pobierz wybrany tarball (URL stały w zmiennej na górze skryptu) do `~/toolchains/`, rozpakuj, znormalizuj nazwę katalogu docelowego. `set -euo pipefail`.

- [ ] **Step 3: Uruchom skrypt i zweryfikuj binarkę testową**

Run:
```bash
ssh dgx-spark 'cd ~/nanotorrent && bash scripts/mips/provision-toolchain.sh && echo "int main(){return 42;}" > test/.scratch/h.c && ~/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc -static -o test/.scratch/h test/.scratch/h.c && file test/.scratch/h'
```
Expected: `ELF 32-bit LSB executable, MIPS, MIPS32 ... statically linked`.

- [ ] **Step 4: Zweryfikuj soft-float z ABI flags**

Run: `ssh dgx-spark 'cd ~/nanotorrent && readelf -A test/.scratch/h | grep -i "fp\|float"'`
Expected: wizerunek bez hard-float (`soft float` w `Tag_ABI_FP_...`/brak `ODD/reginfo hard`).

- [ ] **Step 5: Commit**

```bash
git add scripts/mips/provision-toolchain.sh .gitignore
git commit -m "build(mips): toolchain provisioning script (bootlin mips32el musl soft)"
```

### Task 2: qemu-mipsel user-mode przez docker

**Files:**
- Create: `scripts/mips/qemu-user-run.sh`
- Create: `scripts/mips/Dockerfile.qemu`

**Interfaces:**
- Consumes: binarki mipsel (staticzne) pod repo
- Produces: `scripts/mips/qemu-user-run.sh <ścieżka-wzgl-repo> [args...]` — uruchamia binarkę pod `qemu-mipsel` w dockerze, propaguje exit code; obraz `ntx-qemu:mipsel`.

- [ ] **Step 1: Napisz `scripts/mips/Dockerfile.qemu`**

`FROM ubuntu:24.04`, `apt-get install -y --no-install-recommends qemu-user-static`, binarka qemu: `/usr/bin/qemu-mipsel-static`.

- [ ] **Step 2: Zbuduj obraz**

Run: `ssh dgx-spark 'cd ~/nanotorrent && docker build -t ntx-qemu:mipsel -f scripts/mips/Dockerfile.qemu .'`
Expected: obraz istnieje (`docker images ntx-qemu`).

- [ ] **Step 3: Napisz `scripts/mips/qemu-user-run.sh`**

`docker run --rm -v "$PWD:/repo" <image> /usr/bin/qemu-mipsel-static -0 ntx "/repo/$1" "${@:2}"` (mount RW — testy tworzą pliki store); exit code qemu → exit skryptu (TCG propaguje kod).

- [ ] **Step 4: smoke: hello z Task 1 zwraca 42**

Run: `ssh dgx-spark 'cd ~/nanotorrent && bash scripts/mips/qemu-user-run.sh test/.scratch/h; echo RC=$?'`
Expected: `RC=42`.

- [ ] **Step 5: Commit**

```bash
git add scripts/mips/Dockerfile.qemu scripts/mips/qemu-user-run.sh
git commit -m "build(mips): qemu-mipsel user-mode runner via docker"
```

### Task 3: Cel `make mips` → `ntx-mipsel` w katalogu głównym

**Files:**
- Modify: `Makefile` (nowe zmienne + cel; istniejące cele nietknięte)

**Interfaces:**
- Consumes: toolchain z Task 1
- Produces: `make mips` → `./ntx-mipsel` (statyczny, soft-float); `MIPS_CC` nadpisywalny.

- [ ] **Step 1: Dodaj do Makefile**

```make
MIPS_CC ?= $(HOME)/toolchains/mips32el-linux-musl/bin/mipsel-linux-musl-gcc
mips: $(SRCS) ; $(MIPS_CC) $(CFLAGS) -static -ffunction-sections -Wl,--gc-sections $(VERSION_DEFINE) -o ntx-mipsel $(SRCS) $(LDLIBS)
```
Uwaga: PIE/RELRO (`HARDEN_LDFLAGS`) odpuszczone dla `-static` musl (precedens: cel `static`); `clean` rozszerzyć o `ntx-mipsel`.

- [ ] **Step 2: Zbuduj i sprawdź dowód**

Run: `ssh dgx-spark 'cd ~/nanotorrent && make mips && file ntx-mipsel && ls -l ntx-mipsel && readelf -A ntx-mipsel | grep -i float'`
Expected: `ELF 32-bit ... MIPS, MIPS32 ... statically linked`; soft-float; rozmiar odnotowany w raporcie (nie gate).

- [ ] **Step 3: Smoke pod qemu**

Run: `ssh dgx-spark 'cd ~/nanotorrent && bash scripts/mips/qemu-user-run.sh ntx-mipsel --help; echo RC=$?'` (albo wywołanie bez args — jak CLI ntx zwraca usage; sprawdź `src/ui/ntx_cli.c` co jest bezpiecznym smoke bez sieci i tak go użyj).
Expected: RC=0 i znany output CLI.

- [ ] **Step 4: Brak nadpisań aarch64**

Run: `ssh dgx-spark 'cd ~/nanotorrent && git status --porcelain | grep -E "^ M (ntx|\.test)" ; test $? -eq 1'` (binarki i tak gitignorowane — dodatkowo: `md5sum ntx` przed/po nie istnieje → wystarczy że cel `ntx` się nie przebudował: porównaj `stat -c %Y ntx` przed/po).
Expected: nie zmieniony.

- [ ] **Step 5: Commit**

```bash
git add Makefile
git commit -m "build(mips): make mips target producing static ntx-mipsel at repo root"
```

### Task 4: Suita unit pod qemu-mipsel (`make test-mipsel`)

**Files:**
- Modify: `Makefile` (cel `test-mipsel`, `.PHONY`)
- Create: `scripts/mips/run-suite.sh` (kompiluj test po teście cross, odpalaj pod qemu, zbieraj wyniki)

**Interfaces:**
- Consumes: `MIPS_CC` (Task 3), `scripts/mips/qemu-user-run.sh` (Task 2)
- Produces: `make test-mipsel` — wszystkie `test/t_*.c` skompilowane cross i odpalone, FAIL wypisuje listę; kod wyjścia 0 = zielono.

- [ ] **Step 1: Napisz `scripts/mips/run-suite.sh`**

Pętla po `test/t_*.c`: kompiluj `$(MIPS_CC) $(CFLAGS) -o test/.mipsel.$(basename).tmp $f $(LDLIBS)` (uwaga: testy self-contained `#include ../src/...c` — flagi jak w `make test`), potem `bash scripts/mips/qemu-user-run.sh <bin>`; kumuluj nazwy nieudanych na końcu; usuwaj `.tmp`. Obsługa `NTX_TEST_TIMEOUT_SCALE` — propaguj env do docker run (`-e NTX_TEST_TIMEOUT_SCALE`).

- [ ] **Step 2: Pierwszy przebieg — napraw błędy kompilacji musl/-Werror**

Run: `ssh dgx-spark 'cd ~/nanotorrent && bash scripts/mips/run-suite.sh 2>&1 | tail -40'`
Expected na starcie: mogą paść kompilacje (musl braki, `-Werror`); poprawki portability idą do `test/` albo `src/` z zachowaniem semantyki aarch64; każdą poprawkę potwierdź `make test` na aarch64 (Task 6 gate, tu: szybka kontrolka na ruszanych plikach).

- [ ] **Step 3: Dodaj cel `test-mipsel` do Makefile**

`test-mipsel: ; @bash scripts/mips/run-suite.sh` + `.PHONY`.

- [ ] **Step 4: Przebieg do zielonego (poza timingami)**

Run: `ssh dgx-spark 'cd ~/nanotorrent && make test-mipsel'`
Expected: `ALL PASS` (timingowe mogą jeszcze wisać — Task 5).

- [ ] **Step 5: Commit**

```bash
git add Makefile scripts/mips/run-suite.sh
git commit -m "test(mips): cross-compiled unit suite under qemu-mipsel"
```

### Task 5: Mnożnik timeoutów i 3× zielona suita

**Files:**
- Create: `test/tscale.h`
- Modify: testy timingowe wskazane przez przegrane przebiegi z Task 4 (m.in. kandydaci: `t_dial_backoff.c`, `t_http_proxy_slow.c`, `t_dht_lookup.c`, `t_hash_exchange.c`, `t_netx_route.c`)

**Interfaces:**
- Consumes: env `NTX_TEST_TIMEOUT_SCALE` (domyślnie 1, wartości całkowite ms)
- Produces: `long ts_ms(long base_ms)` w `test/tscale.h` — `base_ms * scale` (scale z env, parsowany raz, przy braku = 1).

- [ ] **Step 1: Napisz `test/tscale.h` + test helpera**

Nowy `test/t_tscale.c`: przy `NTX_TEST_TIMEOUT_SCALE=5`, `ts_ms(100)==500`; przy braku env `ts_ms(100)==100`; przy śmieciu w env → 1. Zbuduj/puszczaj jak inne testy (też na aarch64 — helper musi być neutralny dla natywnego `make test`).

- [ ] **Step 2: Zastosuj mnożnik w testach, które realnie padły pod TCG**

Tylko tam, gdzie zawodzi timing (spanie/waits/okna czasowe) — zamień stałe na `ts_ms(...)`; asercje bez zmian. Notuj każdą zmianę w commicie.

- [ ] **Step 3: Dobierz mnożnik i wymuś 3× zielone z rzędu**

Run (loop w skrypcie): dla kolejnych wartości skali (start 3) `make test-mipsel` ×1; gdy suita zielona — 3 następujące pełne przebiegi pod tę samą skalę.
Expected: `ALL PASS` trzy razy pod rząd; wynik i użyta skala w wiadomości commita.

- [ ] **Step 4: Commit**

```bash
git add test/tscale.h test/t_tscale.c test/<zmienione>.c
git commit -m "test(mips): TCG timeout scaling, 3x green qemu-mipsel suite (scale=N)"
```

### Task 6: Regresja aarch64

**Files:** — (tylko weryfikacja)

**Interfaces:**
- Consumes: całość zmian Task 1–5
- Produces: zielone natywne `make test` + `make ntx` na Sparku.

- [ ] **Step 1: Pełna natywna suita na Sparku**

Run: `ssh dgx-spark 'cd ~/nanotorrent && make ntx && make test'`
Expected: `ALL PASS`, binarka `ntx` przebudowana natywnie (aarch64).

- [ ] **Step 2: (jeśli coś padło) cofnij/napraw zmiany z Task 4/5 aż zielone**

Każda poprawka portability musl nie mogła zmienić zachowania natywnego — jeśli padło, to ona jest winna.

- [ ] **Step 3: Commit (jeśli były poprawki)** + `gitnexus detect_changes({scope:"all"})` jako przegląd gałęzi.

### Task 7 (best-effort): e2e na malta z OpenWrt

**Files:**
- Create: `scripts/mips/Dockerfile.system`
- Create: `scripts/mips/malta-boot.sh`

**Interfaces:**
- Consumes: `ntx-mipsel` (Task 3)
- Produces: `malta-boot.sh` — boot OpenWrt malta LE z lockiem; udokumentowany przebieg: `ntx-mipsel` w gosciu ściąga mały torrent od seedera na hoście (user-net, gateway `10.0.2.2`), checksum OK.

- [ ] **Step 1: Lock + check instancji PRZED jakąkolwiek pracą z qemu-system**

`malta-boot.sh`: `pgrep -f qemu-system-mips` → jeśli żyje: stop z komunikatem (nie dubluj); `mkdir test/.scratch/malta.lock || stop`; `trap rmdir EXIT`. Wszystkie starty qemu-system wyłącznie przez ten skrypt.

- [ ] **Step 2: Pobierz obrazy OpenWrt malta LE (wersję wybiera budujący, np. 23.05.x)**

`openwrt-*-malta-le-generic-kernel.bin` + `...-squashfs-cpio.bin` → `test/.scratch/malta/`.

- [ ] **Step 3: Boot i SSH do gosca**

`qemu-system-mips -M malta -kernel <kernel> -initrd <cpio> -nographic -net user,hostfwd=tcp::2222-:22 -net nic` (w kontenerze z `qemu-system-mips`); loguj boot do pliku; `ssh -p 2222 root@127.0.0.1` (hasło OpenWrt = brak/`root`).

- [ ] **Step 4: Prześlij `ntx-mipsel` i ściągnij torrent**

`scp ntx-mipsel` do gosca; na hoście seeder (python http.server z plikiem + lokalny tracker albo `ntx` jako seed — wybierz najprostsze działające); w goscu `./ntx-mipsel <magnet|torrent>`; weryfikacja sha256 ściągniętego pliku.
Expected: plik zgodny checksumem; output zanotowany w `docs/superpowers/` jako dowód best-effort.

- [ ] **Step 5: Sprzątnięcie QEMU + commit**

Zabij **tylko** swój PID qemu (zapisany w lockdir), usuń lock.
```bash
git add scripts/mips/
git commit -m "test(mips): malta e2e boot scripts (best-effort torrent smoke)"
```
