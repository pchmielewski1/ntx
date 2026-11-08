# riscv64 — przygotowanie środowiska lokalnego (kompilacja + testy)

Dla: człowieka albo lokalnego modelu LLM wykonującego
[`plans/2026-11-07-riscv64-port.md`](plans/2026-11-07-riscv64-port.md).
Design: [`specs/2026-11-07-riscv64-port-design.md`](specs/2026-11-07-riscv64-port-design.md).

Wszystkie komendy uruchamiaj z **katalogu głównego repo** (`/home/user/nanotorrent`), chyba że
napisano inaczej. Wykonuj sekcje po kolei. Jeśli wynik różni się od „Oczekiwane”, **STOP**:
nie improwizuj, zgłoś komendę i jej pełne wyjście.

## 0. Wybierz wariant

Uruchom:

```bash
uname -m; . /etc/os-release; echo "$ID $VERSION_ID"; sudo -n true && echo SUDO_OK; command -v docker
```

| Wynik | Wariant |
|---|---|
| `ubuntu 22.04` lub `ubuntu 24.04` lub `debian 12`/`13`, jest `SUDO_OK` | **A (apt na hoście)** |
| brak `SUDO_OK` (np. DGX Spark: `sudo: /etc/sudo.conf is owned by uid 65534`), jest docker | **B (docker)** |
| inna dystrybucja (Fedora, Arch, …), jest docker | **B (docker)** |
| brak sudo i brak dockera | STOP — zgłoś partnerowi |

Wariant B to **dokładnie ten sam toolchain co GitHub Actions** (Ubuntu 22.04, gcc 11.4,
qemu 6.2, glibc 2.35). Gdy masz wybór i chcesz odtworzyć CI 1:1, wybierz B.

Na hoście DGX Spark (aarch64, Ubuntu 24.04, zepsute sudo) — **zawsze wariant B**.

## A. apt na hoście (Ubuntu 22.04/24.04, Debian 12/13; x86_64 lub aarch64)

```bash
sudo apt-get update
sudo apt-get install -y gcc-riscv64-linux-gnu libc6-dev-riscv64-cross qemu-user make python3 openssl file
```

Uwagi:
- Pakiet `qemu-user` daje `qemu-riscv64`. Jeśli masz już `qemu-user-static`, też zadziała
  (`qemu-riscv64-static`); `scripts/riscv/qemu-user-run.sh` znajdzie oba.
- Sysroot glibc riscv64 ląduje w `/usr/riscv64-linux-gnu` (loader:
  `/usr/riscv64-linux-gnu/lib/ld-linux-riscv64-lp64d.so.1`).
- Na Ubuntu 24.04 cross-libc ma wersję 2.39, a nie 2.35 jak w CI. Do developmentu to
  wystarcza, ale **binarek zbudowanych na 24.04 nie publikuj** — release buduje tylko CI.

Weryfikacja:

```bash
riscv64-linux-gnu-gcc --version | head -1
qemu-riscv64 --version | head -1 || qemu-riscv64-static --version | head -1
ls -l /usr/riscv64-linux-gnu/lib/ld-linux-riscv64-lp64d.so.1
```

Oczekiwane: `riscv64-linux-gnu-gcc (...) 11.x` albo `13.x`; `qemu-riscv64 version 6.2`
albo `8.2`; plik loadera istnieje.

## B. Docker (bez sudo; każda dystrybucja; x86_64 lub aarch64)

Wariant B wymaga plików `scripts/riscv/Dockerfile` i `scripts/riscv/docker-run.sh`. Tworzy
je Task 1 planu. **Zanim Task 1 zostanie wykonany**, używaj komendy jednorazowej z sekcji
B.1. Po Task 1 — B.2.

### B.1 Przed Task 1 (komenda jednorazowa)

```bash
case "$(uname -m)" in x86_64) PLAT=linux/amd64 ;; aarch64|arm64) PLAT=linux/arm64 ;; esac
docker run --rm --platform "$PLAT" ubuntu:22.04 bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq gcc-riscv64-linux-gnu libc6-dev-riscv64-cross qemu-user >/dev/null 2>&1
  riscv64-linux-gnu-gcc --version | head -1; qemu-riscv64 --version | head -1'
```

Oczekiwane:
```
riscv64-linux-gnu-gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
qemu-riscv64 version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.31)
```
(ostatnia liczba wersji Debiana może być wyższa — to jest OK).

### B.2 Po Task 1 (normalna praca)

```bash
bash scripts/riscv/docker-run.sh make riscv          # buduje ./ntx-riscv64
bash scripts/riscv/docker-run.sh make size-riscv
bash scripts/riscv/docker-run.sh make test-riscv     # ~3–8 min
bash scripts/riscv/docker-run.sh make test-riscv-shell
```

Pierwsze wywołanie buduje obraz `ntx-riscv64-env:22.04` (kilka minut, wymaga sieci do
`archive.ubuntu.com` / `ports.ubuntu.com`). Kolejne używają cache. Przebudowa obrazu po
zmianie `Dockerfile`: `docker rmi ntx-riscv64-env:22.04`.

### Pułapki dockera (przeczytaj)

1. **Zawsze `--platform`.** Na hoście aarch64 obraz `ubuntu:22.04` z cache może być amd64 →
   `exec /usr/bin/bash: exec format error`. `docker-run.sh` ustawia platformę sam.
2. **Zawsze `--user "$(id -u):$(id -g)"`.** Bez tego pliki w repo należą do roota (albo
   `nobody` na hostach z user-ns) i potem nie da się ich nadpisać ani usunąć. `docker-run.sh`
   to robi. W tym repo `./ntx` należy już do roota (w sandboksie agenta widoczny jako `nobody:nogroup`) — **nie ruszaj go**.
3. W kontenerze nie ma natywnego `gcc` — to celowe. Natywnych celów (`make ntx`, `make test`)
   nie uruchamiaj przez `docker-run.sh`; uruchamiaj je na hoście.

## C. Weryfikacja środowiska (oba warianty, po Task 1 i Task 2)

Wariant A: wykonuj komendy jak niżej. Wariant B: każdą komendę poza `mkdir`, `md5sum` i
`file` poprzedź `bash scripts/riscv/docker-run.sh`, np.
`bash scripts/riscv/docker-run.sh make riscv NTX_VERSION=0.0.0-dev` i
`bash scripts/riscv/docker-run.sh bash scripts/riscv/qemu-user-run.sh ntx-riscv64 --version`.
Poniżej zapis dla A.

```bash
mkdir -p test/.scratch
md5sum ntx > test/.scratch/ntx-native.md5 2>/dev/null || echo "no native ntx"   # baseline natywnej binarki
make riscv NTX_VERSION=0.0.0-dev
file ntx-riscv64
bash scripts/riscv/qemu-user-run.sh ntx-riscv64 --version
make size-riscv
```

Oczekiwane:
- `file`: `ntx-riscv64: ELF 64-bit LSB pie executable, UCB RISC-V, RVC, double-float ABI, ... dynamically linked, interpreter /lib/ld-linux-riscv64-lp64d.so.1 ...`
- `--version`: `ntx 0.0.0-dev`
- `size-riscv`: linia z rozmiarem około 300 000 B i brak `SIZE FAIL`.
- `md5sum -c test/.scratch/ntx-native.md5` po wszystkim → `ntx: OK`.

## D. Zachowanie testów pod qemu (żeby nie panikować)

- Pełna suita (`make test-riscv`) to 117 programów; na DGX Spark trwała 198 s, na laptopie
  x86_64 spodziewaj się 3–8 min. Najwolniejsze: `t_p256_kat` (~30 s), `t_socks_udp` (~20 s).
- Każdy test ma twardy limit 300 s (`NTX_TEST_TIMEOUT`); przekroczenie = `TIMEOUT` = FAIL.
- Jeśli testy timingowe padają tylko pod qemu na wolnej maszynie:
  `NTX_TEST_TIMEOUT_SCALE=3 make test-riscv`. Nigdy nie zmieniaj asercji ani nie usuwaj
  testów.
- `make test-riscv-shell` zostawia po porażce katalog `test/.scratch/riscv64-shell/` do
  analizy; po sukcesie go usuwa.

## E. Typowe błędy

| Objaw | Przyczyna | Co zrobić |
|---|---|---|
| `make: 'ntx' is up to date.` przy próbie cross | użyto `make ntx CC=...` | używaj `make riscv` |
| `strip: Unable to recognise the format` | hostowy `strip` na binarce RISC-V | `riscv64-linux-gnu-strip` / `NTX_STRIP=riscv64-linux-gnu-strip` |
| `qemu-riscv64: Could not open '/lib/ld-linux-riscv64-lp64d.so.1'` | brak `QEMU_LD_PREFIX` | uruchamiaj przez `scripts/riscv/qemu-user-run.sh` |
| `[qemu-riscv64] ERROR: sysroot missing` | brak `libc6-dev-riscv64-cross` | zainstaluj (A) albo użyj B |
| `exec format error` w dockerze | zła platforma obrazu | `--platform` (B, pułapka 1) |
| `Permission denied` przy `make clean` | pliki roota z dockera | poproś partnera o `sudo chown`; nie kasuj na siłę |
