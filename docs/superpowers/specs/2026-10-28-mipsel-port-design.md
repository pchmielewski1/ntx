# ntx — port na mipsel (OpenWrt) — design

Data: 2026-10-28 · Branch: `mips` (z `publish`) · Status: **zaimplementowany** (bramy unit: `make mips` + 3× `make test-mipsel`; malta e2e best-effort poza zakresem ship)

## Intent i dlaczego

`ntx` (nanotorrent, czysty C11, binarka ~230 KB) działa na x86_64 i aarch64 (dgx-spark).
Partner chce go uruchomić na routerze z OpenWrt. Dowód ukończenia, zgodnie z życzeniem
partnera: **skompilowana binarka mipsel w katalogu głównym projektu + przechodzące testy**.

## Cel (target) — decyzja partnera

- Architektura: **mipsel (`mipsel_24kc`-kompatybilnie)** — MIPS32r2, ABI o32, little-endian.
  Pokrywa mainstream OpenWrt: MediaTek MT7621/MT7620 (ramips) i QCA95xx (ath79).
- **soft-float** (MT7621 nie ma FPU), **musl**, **linkowanie statyczne**.
- Big-endian MIPS, N32/n64, dynamiczne linkowanie — poza zakresem.

## Środowisko budowania i testów — decyzje budującego

- **Build tylko na dgx-spark** (aarch64, 20 rdzeni, docker). Bezwzględny zakaz `make`
  poza Sparkiem — przez sshfs nadpisałby aarch64 binarki/obiekty (lekcja z pamięci projektu).
- **Toolchain**: prebuilt Bootlin `mips32el` / musl / soft (host aarch64; jeśli host aarch64
  niedostępny — fallback: zbudować toolchain w dockerze, np. crosstool-ng, albo OpenWrt SDK
  pod qemu binfmt x86_64). Toolchain poza drzewem repo (np. `~/toolchains/` na Sparku),
  nie w repo.
- **QEMU przez docker** (na hoście Sparka brak qemu): `qemu-user-static` (qemu-mipsel) dla
  suite unit + `qemu-system-mips` (maszyna **malta**, LE) z kernel+rootfs OpenWrt dla smoke
  e2e. Pobrania obrazów malta z downloads.openwrt.org (wersję wybiera budujący).
- **Zasada QEMU (decyzja partnera, twarda)**: QEMU jest wolne i już-bywają-leakują.
  Przed KAŻDYM startem — sprawdzenie czy instancja już działa + lock (wzorzec mkdir-lock
  jak `scripts/start-emulator-host.sh` w ntx-app). Jedna instancja systemowa naraz, testy
  seriami w jednym bootu, nigdy „start/stop na każdy test".

## Artefakty i Makefile

- Binarka docelowa: **`ntx-mipsel` w katalogu głównym repo** (obok aarch64 `ntx`; NIGDY nie
  nadpisuje `ntx` ani obiektów aarch64 — osobne ścieżki build/obiekty, np. `build-mipsel/`).
- Makefile: istniejący `CC ?= cc` pozwala na cross bez zmian; dodać cel `mips`
  (krycie: `make mips` → statyczna binarka mipsel) oraz cele testów qemu
  (np. `test-mipsel-unit`, `test-mipsel-e2e`) — nazwy ostateczne zostawiam budującemu.

## Co mówi rekonesans kodu (stan na branch `mips`)

- 74 pliki `.c`; parser protokołu bit-byte'owy — **zero rzutów na `u16/u32/u64*`**
  (brak ryzyka nie wyrównanych dostępów — główny zabójca MIPS-a).
- Endianness: ręczne przesunięcia, jedyny ślad makr w `src/net/ntx_addr.c`; mipsel jest LE
  jak x86 — logika BE z wire-format nie wymaga zmian.
- `double`: tylko formatowanie UI (`src/ui/ntx_cli.c`) i statystyki prędkości
  (`ntx_peer.h: spd_d`, `ntx_session_data.c`) — soft-float musl wystarczy (wolniej, ale to
  ścieżki nietermowe).
- Syscalle: tylko `epoll_create1/ctl/wait` — musl je realizuje; brak sendfile/splice/mmap
  egzotyki.

## Cele / nie-cele / anty-cele

Cele:
1. `make mips` na Sparku → statyczny ELF mipsel w katalogu głównym repo.
2. Pełna suita unit testów przechodzi pod `qemu-mipsel` (user-mode).
3. Smoke e2e: `ntx-mipsel` startuje i ściąga torrent w qemu-system-mips malta z OpenWrt.
4. Brak regresji na aarch64 (zwykłe `make test` na Sparku nadal zielone).

Nie-cele: mips BE, N32/n64, pakiet opkg, optymalizacje pod routery, CI.

Anty-cele (nawet gdy „technicznie działa"): nadpisanie binarek/obiektów aarch64;
namnożone instancje QEMU; commity binariów narzędzi/toolchainu do repo.

## Rozmiar binarki

ntx ma budżet rozmiaru jako wartość projektu. Budujący notuje rozmiar `ntx-mipsel`
(strip) i raportuje go wobec baseline'a x86_64/aarch64; brak twardego limitu mipsel
ustalonego z góry — raport, nie gate.

## Kryteria akceptacji — decyzje budującego (partner: "decyduj sam")

- **Unit suite = brama**: `make test` pod `qemu-mipsel` (user-mode), **3 pełne zielone
  przebiegi z rzędu**. Żadnych pomijanych testów, żadnych osłabianych asercji; testy
  timingowe dostają mnożnik timeoutów (np. `NTX_TEST_TIMEOUT_SCALE`) aktywny tylko pod
  emulacją — dobierany, nie zgadywany.
- **e2e malta = best-effort** (po zielonej suncie), nie brama akceptacji. Dowód partnera:
  binarka w katalogu głównym + przechodzące testy.
- `test-cli`/`test-net`: best-effort pod qemu-mipsel (ten sam harness); docker-interop
  poza zakresem mips.

## Zostawione budującemu

Wersje: toolchain Bootlin, obraz docker z qemu, wersja OpenWrt malta (kernel+rootfs);
sposób instalacji sysrootu; ewentualne drobne poprawki portability wykryte przy kompilacji
(-Werror może wymagać drobnych fixów pod musl); nazwy celów Makefile i skryptów pomocniczych;
scenariusz torrenta e2e (mały, deterministyczny plik lokalny, bez zależności od netu
publicznego — jeśli dostępny jest już wzorzec w `test/`, użyć go).
