# Prywatne udostępnianie pliku (`--share`) — plan implementacji

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ntx --share=PLIK` (oraz komenda JSON `share`) haszuje plik, tworzy prywatny (BEP 27) hybrydowy torrent v1+v2 z solą, ogłasza go wyłącznie na przypiętych trackerach HTTPS, seeduje go tylko przez MSE i po osiągnięciu gotowości wypisuje magnet oraz zapisuje `.torrent`.

**Architecture:** Nowy moduł udostępniania (`src/core/ntx_share*.c`) tworzy slot torrenta zasilany ze store'u tylko-do-odczytu i działa w istniejącym ticku sesji. Polityki sieciowe (BEP 27, tryb ścisły MSE, §7.1, pule pinów, NAT-PMP/PCP) wchodzą przez wąskie haki, które zadanie kontraktowe wstawia raz do istniejących ścieżek. CLI i JSON tylko konsumują API modułu, a obecny układ UI się nie zmienia.

**Tech Stack:** C11, libc i libm, pętla `epoll` (`ntx_netx`), testy jako samodzielne programy `test/t_*.c` dołączające pliki `.c`, skrypty `sh` i `python3` dla testów i narzędzi, `openssl` tylko w narzędziach opiekuna i CI.

**Spec:** `docs/superpowers/specs/2026-11-08-private-share-design.md`. Numery `§N` w tym planie odnoszą się do tego dokumentu. Wykonawca czyta oba.

## Global Constraints

- Zależności binarki: tylko libc i libm. Żadnych nowych bibliotek, wątków ani blokujących wywołań w pętli.
- `make size`: binarka < 1 MiB (dziś 413 016 B).
- Pojedyncza iteracja pętli ≤ ok. 50 ms (§5.3). Tick sesji wynosi 100 ms.
- Flagi wyłącznie w formie `--opcja=wartość` lub `--flaga`. Istniejące opcje, układ linii statusu i JSON `v` = 1 pozostają bez zmian.
- `private` w metainfo: każda niezerowa liczba oznacza torrent prywatny. `ntx` zapisuje `1` (§4).
- Klucz soli: `ntx salt`, 32 znaki hex z 16 bajtów `ntx_rand_bytes` (§5.2).
- Trackery udostępniania: tylko `https://`, przypięte SPKI, bez TOFU, fail-closed. Minimum `NTX_SHARE_MIN_TRACKERS` = 2 (§6.4).
- Zwykłe `make` i `make test` nie łączą się z siecią. Sieci używają wyłącznie zadanie 0, `make pins-check`/`pins-update` i testy interop.
- Nowe pliki `.c` są dołączane przez testy jak jednostka kompilacji (unity build), więc każda funkcja `static` w nowym pliku ma unikalny prefiks: `share_`, `smeta_`, `sout_`, `priv_`, `pm_`, `pcp_`, `strk_`.
- Komentarze w kodzie tylko dla ograniczeń, których kod nie pokazuje. Styl, nazewnictwo i gęstość komentarzy jak w otaczającym pliku.
- **Uruchamianie pojedynczego testu (strumień X ∈ {A,B,C,I}):**
  `cc -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -o .t_X.tmp test/t_NAME.c -lm && ./.t_X.tmp`.
  W tym planie zapis „`RUN test/t_NAME.c`” oznacza właśnie to polecenie. Każdy strumień kompiluje do własnego pliku `.t_X.tmp`, bo strumienie pracują w jednym drzewie roboczym.
- **Pełny zestaw testów:** `flock /tmp/ntx-maketest.lock make test TEST_BIN=.t_X.tmp`. Blokada jest potrzebna, bo istniejące testy piszą do stałych plików w `test/`.
- **Jedno drzewo robocze, rozłączne pliki.** Strumienie A, B i C pracują w tym samym checkoutcie na `main`, bez worktree. Tylko ten katalog widzi GitNexus (przez sshfs), więc tylko tak `detect_changes` analizuje każdą zmianę. Strumień edytuje wyłącznie pliki ze swojej kolumny w tabeli „Własność plików”. Commit obejmuje tylko własne pliki (`git add <ścieżki>`, nigdy `git add -A` ani `git commit -a`). Wspólny plik nie może zostać w stanie, który się nie kompiluje, dłużej niż trwa jedna edycja.
- **GitNexus (AGENTS.md), repozytorium `ntx`, obowiązkowo:**
  1. Przed edycją istniejącej funkcji, struktury lub makra: `impact({repo:"ntx", target:"<symbol>", direction:"upstream"})`. Wynik (ryzyko, liczba wywołujących i procesów) trafia do treści commita jako linia `impact: <symbol> <RISK>`.
  2. `HIGH`/`CRITICAL`: przerwij i zgłoś koordynatorowi przed edycją. Wyjątkiem są edycje wprost dopuszczone w tym planie (zadanie 1). `UNKNOWN` nie jest zielonym światłem: potwierdź wywołujących przez `rg`.
  3. Przed każdym commitem: `git add <własne pliki>`, potem `detect_changes({repo:"ntx", scope:"staged"})`. Zmienione symbole i procesy muszą pasować do zadania. `partial`/`truncated` = powtórzyć.
  4. Zmiana nazwy symbolu: narzędzie `rename`, nigdy znajdź-i-zamień.
  5. Koordynator po zadaniu 1, po zakończeniu każdego strumienia i po integracji prosi partnera o `gitnexus analyze` na hoście GitNexus (katalog `/home/user/vsc/nanotorrent`). Następnie sprawdza, że `list_repos` pokazuje `lastCommit` = `git rev-parse --short HEAD`. Do tego czasu `impact` widzi stan z poprzedniej fazy. To wystarcza, bo dotyczy symboli istniejących przed fazą.
- **GitNexus (host 192.168.1.108):** kanoniczna nazwa indeksu to `ntx`, ścieżka `/home/user/vsc/nanotorrent` (sshfs → ten checkout). Wpis `ntx-app` usunięty 2026-11-08. `impact`/`context`/`list_repos` używają `repo: "ntx"`. Po `detect_changes` przy czystym drzewie oczekuj 0 plików C; wynik z Kotlinem oznacza, że wrócił zły indeks.
- Ryzyko z analizy wpływu (stan na `31e158f`):
  - `trk_is_dead` i `data_check_torrent_done` mają ryzyko **CRITICAL**. Pierwszej nie edytujemy wcale. Drugą edytuje wyłącznie zadanie 1, w jednej linii.
  - `ntx_session_trk_announce` ma ryzyko **MEDIUM**: wywołujemy ją, nie zmieniamy.
  - `open_part`, `ntx_torrent_set_metainfo`, `sp_plaintext_fallback`, `sp_build_bt_handshake` i `parse_args` mają ryzyko **LOW**.
  - `ntx_ipc_dispatch` i `ntx_stats_to_json` mają ryzyko **UNKNOWN**: wywołujący są w `src/ntx_main.c`, potwierdzeni przez `rg`.
- Commity w stylu repozytorium: `feat(share): …`, `fix(pe): …`, `test(share): …`, `docs: …`, `build: …`, `ci(release): …`.

## Review Focus

1. **Nazwa pliku z `&`, `%`, `#`, `+`, spacją, UTF-8 albo długością bliską 255 B.** Magnet koduje `dn` procentowo i przechodzi round-trip. Nazwa pliku `.torrent` (`<name>-<8hex>.torrent`) nie przekracza `NAME_MAX`: rdzeń nazwy jest przycinany na granicy znaku UTF-8, a nazwa w torrencie zostaje pełna. Testy w zadaniu A4.
2. **Ctrl+C lub JSON `remove` w trakcie hashowania.** Nie powstaje żaden plik `.torrent` ani plik tymczasowy, do trackerów nie idzie `stopped` z zerowym hashem, a zdarzenie `share` dla usuniętego slotu już się nie pojawia. Test w zadaniu A5.
3. **Rozmiary graniczne: 1 B, dokładnie 16 KiB, wielokrotność rozmiaru kawałka, wielokrotność plus 1 B.** Poprawne `pieces`, `pieces root` i obecność albo brak `piece layers` (brak dla pliku ≤ jednego kawałka). Wektory w zadaniu A3.
4. **Plik skrócony lub nieczytelny w trakcie hashowania albo serwowania** (`pread` zwraca mniej lub `EIO`). Hashowanie kończy się błędem `changed` (zmienione metadane `fstat`) albo `io` (błąd odczytu), a serwowanie odrzuca żądania. Proces nie kończy się awarią. Test w zadaniu A6.
5. **Ten sam plik udostępniony dwa razy w jednej sesji przez `--share-from` z tym samym `.torrent`.** Daje to ten sam info-hash w dwóch slotach, co psuje `sp_match_tts`. Druga próba kończy się zdarzeniem błędu `exists`, a pierwsze udostępnienie działa dalej. Test w zadaniu A6.

---

## Własność plików

| Strumień | Pliki (tworzy lub zmienia) |
|---|---|
| Zadanie 0 | `test/trk_http_probe.c`, `docs/network.md` (sekcja badania), `pins.txt` |
| Zadanie 1 | `src/core/ntx_share.h`, `src/core/ntx_session_portmap.h`, `src/proto/ntx_share_trackers.{h,c}`, zaślepki wszystkich nowych `.c`, `src/core/ntx_session_internal.h`, `src/core/ntx_session.h`, `src/core/ntx_torrent.h`, `src/core/ntx_config.h`, `src/ui/ntx_stats.h`, `src/proto/ntx_http.h`, `src/core/ntx_session_stats.c`, a także jednorazowe hunki w `ntx_session.c`, `ntx_session_data.c`, `ntx_session_trk.c` i `ntx_session_peer.c`; `Makefile` (`TEST_BIN`), dołączenia w `test/t_*.c` |
| A | `src/core/ntx_store.{h,c}`, `src/core/ntx_torrent.c`, `src/core/ntx_share.c`, `src/core/ntx_share_meta.{h,c}`, `src/core/ntx_share_out.{h,c}`, `src/core/ntx_session_trk.c`, `src/core/ntx_session_data.c`, `test/scripts/share_gen.py`, `test/vectors/share/`, `test/t_store_ro.c`, `test/t_torrent_validate.c`, `test/t_share_meta.c`, `test/t_share_out.c`, `test/t_share_session.c` |
| B | `src/core/ntx_session_priv.c`, `src/core/ntx_session.c`, `src/core/ntx_session_peer.c`, `src/core/ntx_session_pex.c`, `src/core/ntx_session_meta.c`, `src/core/ntx_session_pe.c`, `src/core/ntx_session_bt_hs.c`, `src/proto/ntx_https_pin.c`, `src/proto/ntx_http.c`, `src/proto/ntx_pcp.{h,c}`, `src/core/ntx_session_portmap.c`, `test/scripts/pcp_vectors.py`, `test/vectors/pcp/`, `test/t_priv_bep27.c`, `test/t_pe_strict.c`, `test/t_share_pins.c`, `test/t_pcp.c`, `test/t_portmap.c`, oraz dostosowanie `test/t_wire_hs.c` i `test/t_session_ext_tx.c` |
| C | `src/ntx_main.c`, `src/ui/*`, `Makefile` (poza `TEST_BIN`), `scripts/pins/`, `.github/workflows/release.yml`, `test/cli_errors.sh`, `test/t_ipc_ctrl.c`, `test/t_cli_tags.c`, `test/interop/ipc/`, `docs/*` (poza sekcją badania), `README.md`, `CHANGELOG.md`, `SECURITY.md` |
| Integracja | `test/interop/share/`, `Makefile` (cel `test-share`) |

Kolejność: zadanie 0 → zadanie 1 → strumienie A, B i C równolegle → zadania I1, I2. Wewnątrz strumienia zadania idą po kolei.

---

### Task 0: Badanie trackerów HTTPS i decyzja o wydaniu (§6.3, §6.4)

Zadanie sekwencyjne, wymaga sieci (`required_permissions: full_network`). Kod produkcyjny się nie zmienia.

**Files:**
- Modify: `test/trk_http_probe.c` (narzędzie testowe: URL-e z `argv` zamiast tablicy `bases`)
- Modify: `docs/network.md` (nowa sekcja „Share tracker survey (2026-11)”)
- Modify: `pins.txt` (wpisy zakwalifikowanych hostów)

**Interfaces:**
- Produces: lista zakwalifikowanych trackerów (URL, host, 1–4 piny hex) dla zadania 1, wpisana do tabeli w `docs/network.md`.

- [ ] **Step 1: Rozszerz `trk_http_probe` o tryb `./trk_http_probe URL...`.** Dla każdego URL-a wysyła dwa announce na świeżo wylosowany hash: najpierw peer_id P1 z portem 40001, potem P2 z portem 40002. Wypisuje `OK <url> peers_for_hash=<n>` albo `FAIL <url> <powód>`. Kryterium §6.3 pkt 3 jest spełnione, gdy odpowiedź dla P2 zawiera port 40001. Bez argumentów narzędzie działa jak dotychczas.
- [ ] **Step 2: Zbuduj i sprawdź narzędzie:** `make probe && ./trk_http_probe https://<znany-działający-tracker>/announce`. Oczekiwane: linia `OK` albo `FAIL` z powodem. Narzędzie nie może się wysypać.
- [ ] **Step 3: Zbierz kandydatów.** Źródła: `https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_https.txt` oraz `https://newtrackon.com/api/stable` (tylko `https://`). Zapisz listę roboczą w `test/.scratch/share-survey.txt` (katalog ignorowany).
- [ ] **Step 4: Dla każdego kandydata sprawdź kryteria §6.3** i zapisz wynik:
  - WebPKI: `openssl s_client -connect HOST:443 -servername HOST -verify_return_error -verify_hostname HOST </dev/null` (kod 0 i `Verify return code: 0`);
  - SPKI: `… | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`;
  - klient TLS `ntx` i announce: krok 1;
  - pełny scrape: `curl -sS --max-time 10 https://HOST/scrape`. Musi zwrócić błąd HTTP, `failure reason` albo pusty słownik `files`.
- [ ] **Step 5: Zapisz wyniki.** W `docs/network.md` dodaj tabelę: host, URL, pin(y), wynik każdego kryterium, decyzja i powód odrzucenia. Zakwalifikowane hosty dopisz do `pins.txt` w istniejącym formacie `<host> <64-hex>`.
- [ ] **Step 6: Bramka decyzji.** Przy ≥ 2 zakwalifikowanych hostach przejdź do zadania 1. Przy mniej niż 2 zatrzymaj plan i zgłoś partnerowi listę z powodami odrzuceń. Partner decyduje, czy kod wchodzi bez wydania funkcji (§6.4). Wtedy zadanie 1 zostawia listę pustą i reszta planu idzie dalej, a bramka jest egzekwowana przez `ntx_share_available()`.
- [ ] **Step 7: Commit.** `git add test/trk_http_probe.c docs/network.md pins.txt`, potem `detect_changes`, potem `git commit -m "docs(network): share tracker survey and pins"`.

---

### Task 1: Wspólny kontrakt, haki i zaślepki

Zadanie sekwencyjne, przed strumieniami. Nie zmienia zachowania programu: `make test` przechodzi bez zmian w istniejących asercjach.

**Files:**
- Create: `src/core/ntx_share.h`, `src/core/ntx_session_portmap.h`, `src/proto/ntx_share_trackers.h`, `src/proto/ntx_share_trackers.c`
- Create (zaślepki): `src/core/ntx_share.c`, `src/core/ntx_share_meta.h`, `src/core/ntx_share_meta.c`, `src/core/ntx_share_out.h`, `src/core/ntx_share_out.c`, `src/core/ntx_session_priv.c`, `src/core/ntx_session_portmap.c`, `src/proto/ntx_pcp.h`, `src/proto/ntx_pcp.c`
- Modify:
  - `src/core/ntx_session_internal.h` (pola i deklaracje haków);
  - `src/core/ntx_torrent.h` (`priv`);
  - `src/core/ntx_config.h` (`port_map`);
  - `src/ui/ntx_stats.h` (pola);
  - `src/proto/ntx_http.h` (`NTX_HTTP_E_PIN`);
  - `src/core/ntx_session_stats.c` (wypełnienie pól, faza `hash`);
  - `src/core/ntx_session.c` (wywołania haków w `ntx_session_tick`, `ntx_session_remove`, `ntx_session_free`);
  - `src/core/ntx_session_data.c:401` oraz dyspozycja PEX i holepunch w `ntx_session_data_on_ext` (ok. `:619-623`);
  - `src/core/ntx_session_trk.c:197,256` i `src/core/ntx_session_peer.c` (`ntx_session_peer_send_ext_handshake`): port przez `ntx_session_adv_port`;
  - `Makefile` (`TEST_BIN ?= .test.tmp` w regule `test`).
- Modify: każdy `test/t_*.c`, który dołącza `src/core/ntx_session.c` (33 pliki) albo `src/proto/ntx_https_pin.c`. Dopisz dołączenia nowych plików `.c` po istniejących.
- Test: `test/t_share_contract.c`

**Interfaces (Produces, obowiązuje wszystkie strumienie):**

```c
/* src/core/ntx_share.h */
#define NTX_SHARE_MAGNET_MAX 4096
#define NTX_SHARE_PATH_MAX 1024
typedef enum { NTX_SHARE_NONE = 0, NTX_SHARE_HASHING, NTX_SHARE_ANNOUNCING,
               NTX_SHARE_READY, NTX_SHARE_FAILED } ntx_share_state;
typedef enum { NTX_SHARE_OK = 0, NTX_SHARE_E_BAD_ARG, NTX_SHARE_E_IO, NTX_SHARE_E_FULL,
               NTX_SHARE_E_NO_TRACKERS, NTX_SHARE_E_TOO_BIG, NTX_SHARE_E_EXISTS,
               NTX_SHARE_E_CHANGED, NTX_SHARE_E_BAD_NAME } ntx_share_err;
typedef struct {
    int i, ok;                 /* slot; 1 = ready, 0 = failed */
    ntx_share_err err;
    uint8_t ih[20], ih2[32];
    char name[512];
    char magnet[NTX_SHARE_MAGNET_MAX];
    char torrent_path[NTX_SHARE_PATH_MAX];
} ntx_share_event;
/* JSON code: "bad_arg","io","full","no_trackers","too_big","exists","changed"; BAD_NAME -> "bad_arg" */
const char *ntx_share_err_code(ntx_share_err e);
const char *ntx_share_err_msg(ntx_share_err e);  /* one-line English text for stderr */
/* Synchronous checks (open, S_ISREG, size, name, trackers, free slot). Returns slot or -1 + *err. */
int ntx_session_share_add(ntx_session *s, const char *path, const char *from_torrent, ntx_share_err *err);
int ntx_session_share_poll_event(ntx_session *s, ntx_share_event *ev); /* 1 = one event dequeued */
ntx_share_state ntx_session_share_state(const ntx_session *s, int ti);
uint32_t ntx_session_share_pct(const ntx_session *s, int ti);        /* 0..100 while HASHING */
int ntx_session_share_serving(const ntx_session *s, int ti);         /* 0 = refuse block requests */
void ntx_session_share_tick(struct ntx_session *s);                  /* every session tick */
void ntx_session_share_on_remove(struct ntx_session *s, int ti);
void ntx_session_share_free(struct ntx_session *s);

/* src/proto/ntx_share_trackers.h */
#define NTX_SHARE_MIN_TRACKERS 2
typedef struct { const char *url, *host; int npins; uint8_t pins[NTX_HTTPS_PIN_MAX][32]; } ntx_share_tracker;
int ntx_share_tracker_count(void);
const ntx_share_tracker *ntx_share_tracker_get(int i);
int ntx_share_available(void);                       /* count >= NTX_SHARE_MIN_TRACKERS */
void ntx_share_trackers_test_set(const ntx_share_tracker *v, int n); /* n < 0: built-in list */

/* src/core/ntx_session_portmap.h — values equal the JSON "port_map" field (§11) */
typedef enum { NTX_PM_OFF = 0, NTX_PM_PENDING = 1, NTX_PM_ACTIVE = 2, NTX_PM_NONE = 3, NTX_PM_CGNAT = 4 } ntx_pm_state;
void ntx_session_portmap_want(struct ntx_session *s, int on); /* share add/remove; honours cfg->port_map */
void ntx_session_portmap_tick(struct ntx_session *s);
void ntx_session_portmap_stop(struct ntx_session *s);         /* lifetime 0, bounded, at exit */
ntx_pm_state ntx_session_portmap_state(const struct ntx_session *s);
uint16_t ntx_session_adv_port(const struct ntx_session *s);   /* ext port when ACTIVE, else listen port */

/* src/core/ntx_session_internal.h — policy hooks (bodies in ntx_session_priv.c, stream B) */
enum { NTX_PSRC_NONE = 0, NTX_PSRC_TRACKER, NTX_PSRC_DHT, NTX_PSRC_PEX, NTX_PSRC_HOLEPUNCH, NTX_PSRC_INBOUND };
int sp_dht_allowed(const struct ntx_session *s, int ti);
int sp_ext_allowed(const struct ntx_session *s, int ti, int ext_local_id);
int sp_dial_allowed(const struct ntx_session *s, int ti, uint8_t src);
```

- Nowe pola `struct ntx_session`:
  - `struct ntx_share_slot *share[NTX_SESSION_MAX_TTS]`;
  - `uint8_t tts_enc_strict[NTX_SESSION_MAX_TTS]`;
  - `uint16_t tts_in_ok[NTX_SESSION_MAX_TTS]`;
  - `uint8_t trk_pin_fail[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK]`;
  - `uint8_t trk_started_ok[NTX_SESSION_MAX_TTS]`;
  - `uint8_t peer_src[NTX_SESSION_MAX_PEERS]`;
  - `struct ntx_portmap *pm`.
- Pozostałe nowe pola:
  - `ntx_torrent`: `uint8_t priv`;
  - `ntx_config`: `int port_map` (−1 = `--no-port-map`, 0 = auto, 1 = `--port-map`, domyślnie 0);
  - `ntx_tts_stat`: `uint8_t priv, share, enc_strict; uint16_t trk_pin_fail, in_ok`;
  - `ntx_stats`: `uint8_t port_map; uint16_t ext_port`;
  - `ntx_http.h`: `#define NTX_HTTP_E_PIN (-2)`.

- [ ] **Step 1: Napisz test `test/t_share_contract.c`** (dołącza ten sam zestaw `.c` co `test/t_session.c` plus nowe pliki):

```c
/* zaślepki zachowują dzisiejsze zachowanie */
assert(ntx_session_adv_port(s) == ntx_netx_port(s->netx));
assert(ntx_session_portmap_state(s) == NTX_PM_OFF);
assert(sp_dht_allowed(s, 0) == (cfg.dht != 0));
assert(sp_ext_allowed(s, 0, NTX_EXT_LOCAL_PEX) == 1);
assert(sp_dial_allowed(s, 0, NTX_PSRC_PEX) == 1);
assert(ntx_session_share_state(s, 0) == NTX_SHARE_NONE);
ntx_share_trackers_test_set(NULL, 0);
ntx_share_err e = NTX_SHARE_OK;
assert(ntx_session_share_add(s, "test/t_share_contract.c", NULL, &e) == -1 && e == NTX_SHARE_E_NO_TRACKERS);
assert(!strcmp(ntx_share_err_code(NTX_SHARE_E_BAD_NAME), "bad_arg"));
assert(!strcmp(ntx_share_err_code(NTX_SHARE_E_NO_TRACKERS), "no_trackers"));
ntx_stats st; ntx_session_snapshot(s, &st);
assert(st.port_map == 0 && st.ext_port == 0);
```

- [ ] **Step 2: Uruchom test i sprawdź, że się nie kompiluje.** `RUN test/t_share_contract.c`. Oczekiwane: błąd kompilacji, nieznane `ntx_share.h` i symbole.
- [ ] **Step 3: Analiza wpływu przed edycjami.** `impact` dla `data_check_torrent_done` (CRITICAL: edycja **dopuszczona** w tym zadaniu, tylko linia 401), `ntx_session_data_on_ext`, `ntx_session_tick`, `ntx_session_remove`, `ntx_session_free`, `trk_http_announce`, `ntx_session_peer_send_ext_handshake` i `stats_fill_phase`. Wyniki zapisz w commicie.
- [ ] **Step 4: Utwórz nagłówki i zaślepki z sekcji Interfaces.**
  - Zaślepki odtwarzają dzisiejsze zachowanie: `sp_dht_allowed` zwraca `s->cfg && s->cfg->dht`, `sp_ext_allowed` i `sp_dial_allowed` zwracają 1, `ntx_session_adv_port` zwraca `ntx_netx_port(s->netx)`.
  - `ntx_session_share_add` zwraca −1 z `NO_TRACKERS`, gdy `!ntx_share_available()`, w przeciwnym razie −1 z `BAD_ARG`.
  - `ntx_share_trackers.c` zawiera listę z zadania 0 (pusta, jeśli bramka nie przeszła). Dane z lub bez `-DNTX_SHARE_TRACKERS_INC="plik"` dołączane są przez `#include NTX_SHARE_TRACKERS_INC`; ścieżki tej używa zadanie C4.
- [ ] **Step 5: Wstaw haki.**
  - W `data_check_torrent_done` zamień `if (s->cfg && s->cfg->dht)` na `if (sp_dht_allowed(s, tts_idx))`.
  - W `ntx_session_data_on_ext` owiń wywołanie `ntx_session_holepunch_on_rx` warunkiem `sp_ext_allowed(s, s->peer_tts[pi], NTX_EXT_LOCAL_HOLEPUNCH)`, a wywołanie `ntx_session_data_on_pex` warunkiem `sp_ext_allowed(s, s->peer_tts[pi], NTX_EXT_LOCAL_PEX)`.
  - Zamień trzy użycia `ntx_netx_port(s->netx)` (announce UDP, announce HTTP, ext-handshake) na `ntx_session_adv_port(s)`.
  - W `ntx_session_tick` wywołaj `ntx_session_share_tick` i `ntx_session_portmap_tick`. W `ntx_session_remove` wywołaj `ntx_session_share_on_remove` przed zwolnieniem slotu. W `ntx_session_free` wywołaj `ntx_session_portmap_stop` oraz `ntx_session_share_free`.
  - W `stats_fill_phase` wypełnij nowe pola. Gdy `ntx_session_share_state == NTX_SHARE_HASHING`, ustaw `phase = "hash"` i `pct = ntx_session_share_pct`. Pole `share` = 1 dla stanów HASHING..READY i 2 dla FAILED.
- [ ] **Step 6: Dopisz dołączenia nowych `.c` w testach i `TEST_BIN` w `Makefile`.** Testy dołączające `ntx_session.c` dostają wszystkie siedem nowych plików `.c`. Testy dołączające tylko `ntx_https_pin.c` dostają `ntx_share_trackers.c`.
- [ ] **Step 7: Uruchom test kontraktu i pełny zestaw.** `RUN test/t_share_contract.c`, potem `flock /tmp/ntx-maketest.lock make test TEST_BIN=.t_1.tmp`, potem `make ntx && make size`. Oczekiwane: `PASS` w teście kontraktu, `ALL PASS`, a rozmiar < 1 MiB.
- [ ] **Step 8: Commit i reindeks.** `git add` plików z wiersza „Zadanie 1”, potem `detect_changes(staged)`. Oczekiwane: jedyna zmiana w procesach CRITICAL to linia DHT w `data_check_torrent_done`. Następnie `git commit -m "feat(share): contract headers, policy hooks and stubs"`. Koordynator prosi partnera o `gitnexus analyze` (Global Constraints, punkt GitNexus 5).

---

## Strumień A — rdzeń udostępniania

### Task A1: Store tylko-do-odczytu (§5.1)

**Files:**
- Modify: `src/core/ntx_store.h`, `src/core/ntx_store.c`
- Test: `test/t_store_ro.c`

**Interfaces:**
- Produces:
  - `int ntx_store_open_ro_fd(ntx_store *st, int fd, uint64_t size, uint32_t ps);` Zwraca 0 albo −1. Store nie zamyka `fd` przy `ntx_store_close`, bo deskryptor należy do udostępnienia.
  - Pole `uint8_t ro` w `ntx_store`.
  - `ntx_store_write` na store z `ro` zwraca −1.

- [ ] **Step 1: Napisz test `t_store_ro.c`.** Utwórz plik 40 000 B i otwórz go `O_RDONLY`. Następnie: `ntx_store_open_ro_fd(&st, fd, 40000, 16384) == 0`, `st.np == 3`, a `ntx_store_read` zwraca te same bajty co plik. Dalej `ntx_store_write(&st, 0, 0, buf, 16) == -1` i plik po teście jest bajt w bajt taki sam (porównanie SHA-1). Po `ntx_store_close(&st)` `fcntl(fd, F_GETFD) != -1`. W katalogu testu nie powstał żaden nowy plik (porównanie listy `readdir` przed i po).
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_store_ro.c`. Oczekiwane: błąd kompilacji, brak `ntx_store_open_ro_fd`.
- [ ] **Step 3: Zaimplementuj.** Najpierw `impact` dla `ntx_store_write` i `ntx_store_close`. Store RO ma jedną część `{fd, 0, size}` i `pmap` alokowane jak w `ntx_store_open`. Bez `open_part`, `ftruncate` i `mkdir_p_parent`.
- [ ] **Step 4: Uruchom test i sprawdź, że przechodzi.** `RUN test/t_store_ro.c`, potem `RUN test/t_store.c`. Oczekiwane: `PASS` w obu.
- [ ] **Step 5: Commit.** `git add src/core/ntx_store.[ch] test/t_store_ro.c`, `detect_changes`, `git commit -m "feat(store): read-only store over a caller-owned fd"`.

### Task A2: Walidacja metainfo bez efektów na dysku i flaga `private` (§4, §5.2)

**Files:**
- Modify: `src/core/ntx_torrent.c` (`ntx_torrent_set_metainfo`, `tt_set_metainfo_v1` `:152`, otwarcie store `:218-276`, ścieżka v2 `:511-531`), `src/core/ntx_torrent.h`
- Test: `test/t_torrent_validate.c`

**Interfaces:**
- Produces:
  - `int ntx_torrent_validate_metainfo(ntx_torrent *t, const uint8_t *info, size_t info_n, const uint8_t *layers, size_t layers_n);` Wypełnia pola torrenta (hashe, `name`, `ps`, `np`, `size`, `priv`, pola v2) **bez** otwierania store'u. Zwraca 0 albo −1.
  - `int ntx_torrent_open_store(ntx_torrent *t, const char *store_dir);` To dzisiejsza ścieżka zapisu.
  - `ntx_torrent_set_metainfo` = `validate` + `open_store`, z niezmienioną sygnaturą i zachowaniem.
  - `t->priv` = 1 dla każdej niezerowej liczby całkowitej w `info.private`, 0 przy braku klucza albo innym typie.
- Consumes: `ntx_store_open_ro_fd` (A1) dopiero w A5. Tutaj go nie używaj.

- [ ] **Step 1: Napisz test `t_torrent_validate.c`.** Użyj `test/vectors/bep52/hybrid_ok/meta.torrent` z pustym katalogiem tymczasowym jako `store_dir`. Po `ntx_torrent_validate_metainfo` sprawdź `== 0`, hashe zgodne z `manifest.txt` i katalog nadal pusty. Wariant z `private` = `i1e`, `i7e`, `i-1e` daje `t.priv == 1`. Wariant z `1:1` (łańcuch) oraz bez klucza daje `t.priv == 0`. Na koniec `ntx_torrent_set_metainfo` na tym samym wejściu tworzy plik w `store_dir`, jak dziś.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_torrent_validate.c`. Oczekiwane: błąd kompilacji.
- [ ] **Step 3: Rozdziel funkcję.** Najpierw `impact` dla `ntx_torrent_set_metainfo`, `tt_set_metainfo_v1` i ścieżki v2. Kod otwierający store przenieś do `ntx_torrent_open_store`, a odczyt `private` dodaj w walidacji.
- [ ] **Step 4: Uruchom test i pełny zestaw.** `RUN test/t_torrent_validate.c`, potem `flock … make test TEST_BIN=.t_A.tmp`. Oczekiwane: `PASS` i `ALL PASS`.
- [ ] **Step 5: Commit** `feat(torrent): side-effect-free metainfo validation, private flag`.

### Task A3: Hasher i generator metainfo (§5.2, §5.3)

**Files:**
- Create: `src/core/ntx_share_meta.h`, `src/core/ntx_share_meta.c` (zastępują zaślepki), `test/scripts/share_gen.py`, `test/vectors/share/{tiny_1b,one_piece_16k,multi_tail,exact_multi}/` (każdy z plikami `data.bin`, `salt.txt`, `trackers.txt`, `info.bin`, `meta.torrent`, `manifest.txt`)
- Test: `test/t_share_meta.c`

**Interfaces:**
- Produces:

```c
int smeta_piece_len(uint64_t size, uint32_t *ps);   /* 0 ok; -1 when pieces would exceed 32768 */
typedef struct ntx_share_hasher ntx_share_hasher;   /* opaque, heap */
ntx_share_hasher *ntx_share_hasher_new(uint64_t size, uint32_t ps);
int ntx_share_hasher_feed(ntx_share_hasher *h, const uint8_t *buf, size_t n); /* sequential bytes */
int ntx_share_hasher_done(const ntx_share_hasher *h);
const uint8_t *ntx_share_hasher_sha1(const ntx_share_hasher *h);      /* np*20 */
const uint8_t *ntx_share_hasher_root(const ntx_share_hasher *h);      /* 32 */
const uint8_t *ntx_share_hasher_layer(const ntx_share_hasher *h, size_t *n); /* np*32, NULL when np==1 */
void ntx_share_hasher_free(ntx_share_hasher *h);
/* bencoded info dict and full .torrent; trackers = full share list order */
int ntx_share_build_info(const ntx_share_hasher *h, const char *name, const char salt_hex[33],
                         uint8_t **info, size_t *info_n);
int ntx_share_build_torrent(const uint8_t *info, size_t info_n, const ntx_share_hasher *h,
                            const char *const *trackers, int ntrk, int64_t creation_date,
                            uint8_t **out, size_t *out_n);
```

- Wartości wymagane przez §5.2:
  - klucze `info` w porządku bajtowym: `file tree`, `length`, `meta version`=2, `name`, `ntx salt`, `piece length`, `pieces`, `private`=1;
  - poziom główny: `announce`, `announce-list` (jedna warstwa na tracker), `created by` = `ntx/` NTX_VERSION, `creation date`, `info`, `piece layers` (tylko gdy np > 1).
- Rozmiar kawałka: najmniejsza potęga 2 w [16 KiB, 64 MiB] dająca ≤ 2048 kawałków, inaczej 64 MiB. Odmowa przy > 32 768 kawałkach.

- [ ] **Step 1: Napisz generator `test/scripts/share_gen.py`.** Generator jest niezależny od kodu C: hashlib, ręczny bencode i drzewo Merkle z liśćmi 16 KiB, dopełnione do potęgi 2 haszami zerowymi zgodnie z BEP 52. Tworzy cztery fiksury o rozmiarach 1 B, 16 384 B, 3×16 384+100 B i 4×16 384 B, ze stałą solą `00112233445566778899aabbccddeeff`, dwoma trackerami testowymi i `creation date` = 1700000000. W `manifest.txt` zapisuje `ps`, `np`, `ih_sha1`, `ih_sha256` i `has_layers`. Uruchom: `python3 test/scripts/share_gen.py`.
- [ ] **Step 2: Napisz test `t_share_meta.c`.**
  - `smeta_piece_len`: 1 B daje 16384; 2048×16 KiB daje 16384; 2048×16 KiB+1 daje 32768; 2048×64 MiB daje 64 MiB; 32768×64 MiB daje 64 MiB i 0; 32768×64 MiB+1 daje −1.
  - Dla każdej fiksury podawaj `data.bin` do hashera kawałkami po 7 919 B. Wynik `ntx_share_build_info` jest bajt w bajt równy `info.bin`, a `ntx_share_build_torrent` równy `meta.torrent`.
  - `ntx_torrent_validate_metainfo` (A2) na zbudowanym `info` i warstwach daje 0, `priv == 1` i hashe z `manifest.txt`.
- [ ] **Step 3: Uruchom test i sprawdź, że pada.** `RUN test/t_share_meta.c`. Oczekiwane: błąd kompilacji.
- [ ] **Step 4: Zaimplementuj `ntx_share_meta.c`.** Użyj `ntx_sha1`, `ntx_sha256` i istniejącego `ntx_merkle_*`. Budowa warstwy z liści per kawałek: tak samo jak `ntx_merkle_file_layer`, ale przyrostowo. Hasher trzyma tylko bieżący kawałek i hashe liści.
- [ ] **Step 5: Uruchom test.** `RUN test/t_share_meta.c`. Oczekiwane: `PASS` dla czterech fiksur i reguły rozmiaru.
- [ ] **Step 6: Commit** `feat(share): incremental hasher and private hybrid metainfo builder`.

### Task A4: Magnet i zapis `.torrent` (§5.4)

**Files:**
- Create: `src/core/ntx_share_out.h`, `src/core/ntx_share_out.c`
- Test: `test/t_share_out.c`

**Interfaces:**
- Produces:

```c
/* magnet:?xt=urn:btih:<40hex>&xt=urn:btmh:1220<64hex>&dn=<pct>&tr=<pct>... ; RFC 3986 unreserved stay raw */
int ntx_share_magnet(char *out, size_t cap, const uint8_t ih[20], const uint8_t ih2[32],
                     const char *name, const char *const *trackers, int ntrk);
/* <dir>/<stem>-<8 hex of ih>.torrent, stem cut on a UTF-8 boundary so the basename fits NAME_MAX */
int ntx_share_torrent_path(char *out, size_t cap, const char *dir, const char *name, const uint8_t ih[20]);
/* tmp in same dir + fsync + rename, mode 0600; existing same bytes -> overwrite; other ih -> NTX_SHARE_E_EXISTS */
ntx_share_err ntx_share_write_torrent(const char *path, const uint8_t *buf, size_t n, const uint8_t ih[20]);
int ntx_share_name_ok(const char *name); /* valid UTF-8, no bytes < 0x20 or 0x7f, no '/', non-empty */
```

- [ ] **Step 1: Napisz test `t_share_out.c`.**
  - Magnet dla nazwy `a b&c%d#e+ł.bin` i dwóch trackerów: `ntx_magnet_parse` daje `info_hash == ih`, `has_v2 == 1`, `ih_v2 == ih2`, `name` równe oryginałowi i `n_trackers == 2`.
  - Ścieżka dla nazwy 250 B (UTF-8, ostatni znak 2-bajtowy na granicy): `strlen(basename) <= 255`, kończy się `-<8hex>.torrent` i nie przecina znaku.
  - Zapis: tryb `0600` (`stat`), brak plików `*.tmp*` po sukcesie, drugi zapis tych samych bajtów daje `NTX_SHARE_OK`, a plik z innym `ih` daje `NTX_SHARE_E_EXISTS` i stary plik jest nietknięty.
  - `ntx_share_name_ok`: odrzuca `"a/b"`, `"\x01x"`, `"\x7f"`, `"\xc3\x28"` i `""`; przyjmuje `"zażółć.txt"`.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_share_out.c`. Oczekiwane: błąd kompilacji.
- [ ] **Step 3: Zaimplementuj `ntx_share_out.c`.** Rozpoznanie „ten sam hash” w istniejącym pliku: parsuj go `ntx_be_parse` i porównaj SHA-1 surowego `info`.
- [ ] **Step 4: Uruchom test.** `RUN test/t_share_out.c`. Oczekiwane: `PASS`.
- [ ] **Step 5: Commit** `feat(share): magnet builder and atomic 0600 .torrent writer`.

### Task A5: Cykl życia udostępnienia w sesji (§5.3, §5.5)

**Files:**
- Modify: `src/core/ntx_share.c` (zastępuje zaślepkę), `src/core/ntx_session_trk.c` (`trk_note_ok` `:38`, `trk_http_announce` `:250`), `src/core/ntx_session_data.c` (`data_ratio_threshold_hit`, `data_serve`)
- Test: `test/t_share_session.c`

**Interfaces:**
- Consumes: A1–A4, `ntx_share_tracker_get` (zad. 1), `ntx_session_portmap_want` i `ntx_session_portmap_state` (zad. 1; zaślepka zwraca `NTX_PM_OFF`), `ntx_session_trk_announce` (wywołanie, bez zmian), `NTX_HTTP_E_PIN`.
- Produces:
  - pełna implementacja API `ntx_share.h` z zadania 1, bez `from_torrent` (to zadanie A6);
  - hook testowy `void ntx_share_test_advance_ms(uint64_t ms);`, który przesuwa zegar udostępnień (backoff trackerów, ostrzeżenie po 60 s, `fstat` co 1 s). Zegar udostępnień = `ntx_mono_ms()` + przesunięcie.

Zachowanie, które musi wynikać z kodu:

1. `share_add` wykonuje §5.1 synchronicznie:
   - `open(O_RDONLY|O_CLOEXEC)`, `fstat`, `S_ISREG`, rozmiar > 0;
   - nazwa przez `ntx_share_name_ok(basename)`;
   - `smeta_piece_len` (błąd daje `TOO_BIG`);
   - `ntx_share_available()`;
   - `ntx_session_free_slot`.
2. Po sukcesie slot ma:
   - `state = NTX_TTS_VERIFY`, `info_hash` z 20 zer;
   - `trk_urls` z pełnej listy udostępniania;
   - `tts_enc_strict[ti] = 1`, `priv = 1`;
   - wywołane `ntx_session_portmap_want(s, 1)`.
3. Tick hashuje przez `pread` z budżetem czasowym ≤ 20 ms na tick (`ntx_mono_ms`). Budżet zapisz jako `#define NTX_SHARE_HASH_BUDGET_MS 20`.
4. Po hashowaniu kolejno:
   - zbuduj `info` (sól z `ntx_rand_bytes`) i przepuść go przez `ntx_torrent_validate_metainfo`;
   - otwórz store przez `ntx_store_open_ro_fd`;
   - oznacz wszystkie kawałki jako mające i ustaw `pre_complete = 1`;
   - sprawdź duplikat hasha w innym żywym slocie (daje `EXISTS`);
   - zapisz `.torrent` (A4) do `cfg->store_dir`;
   - ustaw stan `NTX_TTS_DONE` i share `ANNOUNCING`.

   Nie wywołuj `data_check_torrent_done`.
5. Pierwszy announce `NTX_TRACKER_EVENT_STARTED` idzie dopiero, gdy `ntx_session_portmap_state` ∉ {`NTX_PM_PENDING`}. `left` = 0 wynika z `trk_left`.
6. `trk_note_ok` ustawia `s->trk_started_ok[ti] = 1`. Share przechodzi w `READY`, gdy ta flaga jest ustawiona po starcie. Wtedy kolejkuje zdarzenie `ok=1` z magnetem.
7. `trk_http_announce`: gdy `ntx_http_get` zwraca `NTX_HTTP_E_PIN`, ustaw `s->trk_pin_fail[ti][k] = 1` i `trk_fail[ti][k] = NTX_TRK_MAX_FAIL`. `trk_is_dead` pozostaje bez zmian.
8. Wznawianie martwych trackerów udostępnienia odbywa się w `ntx_session_share_tick`, bez edycji `trk_is_dead`:
   - dotyczy wpisów z `trk_fail >= NTX_TRK_MAX_FAIL` i `!trk_pin_fail`;
   - po upływie backoffu (300 s, podwajane do 3600 s, licznik per tracker w `ntx_share_slot`) ustaw `trk_fail = NTX_TRK_MAX_FAIL - 1` i `trk_next[ti] = 0`.
9. Ostrzeżenia na stderr przez `ntx_diag`: jedno po 60 s bez `READY`. Gdy wszystkie trackery mają `trk_pin_fail`, komunikat §5.5 („keys in this ntx build are out of date or a MITM is in progress; update ntx”).
10. `data_ratio_threshold_hit` zwraca 0 dla slotów z `s->share[ti] != NULL`. `data_serve` odrzuca żądanie, gdy `!ntx_session_share_serving(s, ti)`.
11. `on_remove` i `free`:
    - zamyka `fd`, zwalnia hasher i slot;
    - gdy to ostatnie udostępnienie, wywołuje `ntx_session_portmap_want(s, 0)`;
    - podczas `HASHING` nie wysyła `stopped`, bo hash jeszcze nie istnieje, a zakolejkowane zdarzenia tego slotu są usuwane.

- [ ] **Step 1: Napisz test `t_share_session.c`.** Sesja z loopbackowym `ntx_netx` jak w `t_session_trk_http_peers.c`. Trackery testowe przez `ntx_share_trackers_test_set` to `http://127.0.0.1:<port>/announce`, obsługiwane przez lokalny nasłuch TCP jak w `t_session_trk_stop.c`, który liczy żądania i odpowiada poprawnym słownikiem. Wymóg HTTPS egzekwuje lista i `pins.py` (C4), nie ten moduł. Przypadki:
  - `share_add` dla katalogu daje `IO`, dla pustego pliku `IO`, dla nazwy `"\x01"` `BAD_NAME`, a przy dwóch trackerach testowych zwraca slot ≥ 0;
  - przed końcem hashowania: stan `VERIFY`, faza `hash` w `ntx_session_snapshot`, `ih` z zerami;
  - pomiar: żaden pojedynczy `ntx_session_tick` przy pliku 64 MiB nie trwa > 50 ms;
  - po hashowaniu: istnieje `<store>/<name>-<8hex>.torrent`, nie istnieje `<store>/<name>`, plik źródłowy ma niezmienione `mtime` i bajty;
  - po odpowiedzi lokalnego trackera na `started` (żądanie zawiera `left=0` i `event=started`): dokładnie jedno zdarzenie `ok=1`, `magnet` przechodzi `ntx_magnet_parse` i jego hash jest równy `t->info_hash`;
  - **(Review Focus 2)** `ntx_session_remove` w trakcie hashowania: brak pliku `.torrent` i `*.tmp*`, `poll_event` daje 0, a lokalny tracker nie dostał żadnego żądania;
  - pin-fail: wywołanie ścieżki z `NTX_HTTP_E_PIN` daje `trk_pin_fail[ti][k] == 1` i brak wznowienia po `ntx_share_test_advance_ms(3600000)`;
  - zwykły błąd: wznowienie po 300 s, potem po 600 s;
  - ratio: `tts_up` = 10×rozmiar nie zmienia stanu seedowania.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_share_session.c`. Oczekiwane: FAIL na pierwszej asercji po zaślepce.
- [ ] **Step 3: Analiza wpływu.** `impact` dla `trk_note_ok`, `trk_http_announce`, `data_ratio_threshold_hit` i `data_serve`. Przy HIGH/CRITICAL zatrzymaj się i zgłoś.
- [ ] **Step 4: Zaimplementuj** zachowanie z punktów 1–11.
- [ ] **Step 5: Uruchom test i pełny zestaw.** `RUN test/t_share_session.c`, potem `flock … make test TEST_BIN=.t_A.tmp`. Oczekiwane: `PASS` i `ALL PASS`.
- [ ] **Step 6: Commit** `feat(share): session lifecycle, readiness, tracker revival, ratio exemption`.

### Task A6: `--share-from`, wykrywanie zmian i błędy odczytu (§5.5, §5.6)

**Files:**
- Modify: `src/core/ntx_share.c`
- Test: `test/t_share_session.c` (nowe przypadki)

**Interfaces:**
- Consumes:
  - `ntx_session_share_add(s, path, from_torrent, &err)` z `from_torrent != NULL`;
  - `.torrent` czytany `ntx_be_parse` i walidowany przez `ntx_torrent_validate_metainfo`.

  Wymagane: `priv == 1`, jeden plik i `length` równe rozmiarowi pliku. W przeciwnym razie błąd synchroniczny `BAD_ARG`.
- Produces: weryfikacja w fazie `hash`, w której hasher porównuje SHA-1 i warstwy z `.torrent`. Niezgodność daje zdarzenie `CHANGED`. `.torrent` nie jest przepisywany, a magnet jest budowany z aktualnej listy trackerów.

Zachowanie:

- Co 10 ticków (1 s) `fstat` na `fd` i porównanie `st_dev`, `st_ino`, `st_size`, `st_mtim` i `st_ctim` z wartościami zapisanymi po hashowaniu. Różnica daje `FAILED`/`CHANGED`:
  - choke wszystkich peerów slotu;
  - `ntx_session_trk_announce(…, NTX_TRACKER_EVENT_STOPPED)`;
  - zdarzenie `ok=0`.
- Krótki odczyt albo `EIO` w trakcie hashowania daje `IO`, a w trakcie serwowania odrzucenie żądania i przejście w `FAILED`/`IO`.

- [ ] **Step 1: Dopisz przypadki testowe.**
  - `--share-from` z `.torrent` z A5 i tym samym plikiem: ten sam `ih` oraz `.torrent` niezmieniony (porównanie bajtów i `mtime`).
  - Zmieniony 1 bajt w kopii pliku: zdarzenie `ok=0`, `err == NTX_SHARE_E_CHANGED`.
  - `.torrent` publiczny albo z innym `length`: −1 i `BAD_ARG`.
  - **(Review Focus 5)** drugi `--share-from` tego samego `.torrent` w tej samej sesji daje zdarzenie `EXISTS`, a pierwszy slot nadal `READY`.
  - **(Review Focus 4)** `ftruncate` kopii źródła do połowy w trakcie hashowania daje `CHANGED` albo `IO` i sesja działa dalej. Po `READY` `ftruncate` daje w ciągu ≤ 2 s `CHANGED`, a `data_serve` odrzuca żądanie.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_share_session.c`. Oczekiwane: FAIL na nowych przypadkach.
- [ ] **Step 3: Zaimplementuj** zachowanie opisane wyżej.
- [ ] **Step 4: Uruchom test i pełny zestaw.** `RUN test/t_share_session.c`, potem `flock … make test TEST_BIN=.t_A.tmp`. Oczekiwane: `PASS` i `ALL PASS`.
- [ ] **Step 5: Commit** `feat(share): re-share from .torrent with full verification, change detection`.

---

## Strumień B — bezpieczeństwo sieci i osiągalność

### Task B1: Źródło peera i reguły BEP 27 (§4)

**Files:**
- Modify:
  - `src/core/ntx_session_priv.c` (polityki);
  - `src/core/ntx_session.c` (`ntx_session_add_peer_dial_ex` zapisuje `peer_src`, lookup DHT `:171`, callback DHT `:123`);
  - `src/core/ntx_session_peer.c` (`ntx_session_peer_send_ext_handshake`, przyjęcie połączenia przychodzącego ustawia `NTX_PSRC_INBOUND`);
  - `src/core/ntx_session_pex.c` (wywołania `ntx_session_add_peer_from_tracker` `:27,:33` z `NTX_PSRC_PEX`, nadawanie PEX);
  - `src/core/ntx_session_meta.c` (`meta_assemble`: przejście magnet → private);
  - `src/core/ntx_session_trk.c` nie jest zmieniany: tracker zostaje domyślnym źródłem.
- Test: `test/t_priv_bep27.c`; dostosowanie `test/t_session_ext_tx.c`

**Interfaces:**
- Produces:
  - `int ntx_session_add_peer_src(struct ntx_session *s, int ti, const ntx_addr *a, uint16_t port, uint8_t src);` Zwraca 1, gdy dial ruszył. `ntx_session_add_peer_from_tracker` = `…_src(…, NTX_PSRC_TRACKER)`.
  - Polityki:
    - `sp_dht_allowed` = `cfg->dht && !t->priv`;
    - `sp_ext_allowed` = 0 dla PEX i holepunch, gdy `t->priv`;
    - `sp_dial_allowed` = `!t->priv || src == NTX_PSRC_TRACKER`.

- [ ] **Step 1: Napisz test `t_priv_bep27.c`.**
  - Slot z `priv = 1`: ext-handshake (przechwycony z bufora wyjściowego peera) nie zawiera `ut_pex` ani `ut_holepunch`, a zawiera `ut_metadata`.
  - Przychodzący PEX z adresem 10.9.9.9 nie tworzy dialu.
  - `connect` holepunch jest ignorowany (`hp_rx_connect` bez zmian).
  - `ntx_session_add_peer_src(…, NTX_PSRC_DHT) == 0`.
  - Przy `cfg.dht = 1` `sp_dht_allowed == 0`.
  - Slot publiczny: wszystkie powyższe działają jak dziś.
  - Przejście magnet → private: dwa peery wychodzące (źródło TRACKER i DHT) i jeden przychodzący. Po `meta_assemble` z `info` zawierającym `private` = 1 zostaje peer TRACKER i przychodzący, a peer DHT jest zamknięty (`peers[pi].fd == -1`).
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_priv_bep27.c`. Oczekiwane: FAIL, bo zaślepki dopuszczają wszystko.
- [ ] **Step 3: Analiza wpływu.** `impact` dla `ntx_session_add_peer_dial_ex`, `ntx_session_peer_send_ext_handshake`, `ntx_session_data_on_pex`, `meta_assemble` i `dht_peers_cb`. Przy HIGH/CRITICAL zgłoś.
- [ ] **Step 4: Zaimplementuj.**
  - `peer_src[pi]` ustawiany przy alokacji slotu peera.
  - Nadawanie PEX (`ntx_session_data_pex_tick`) pomija sloty prywatne.
  - Lookup DHT dla magnetu jest przerywany po wykryciu `priv`: wyniki callbacku dla prywatnego slotu są odrzucane.
- [ ] **Step 5: Uruchom testy.** `RUN test/t_priv_bep27.c`, `RUN test/t_session_ext_tx.c`, `RUN test/t_pex_outbound.c`, `RUN test/t_dht_session.c`. Oczekiwane: `PASS` we wszystkich.
- [ ] **Step 6: Commit** `feat(bep27): private torrents skip DHT, PEX, holepunch and non-tracker dials`.

### Task B2: Tryb ścisły MSE i przychodzący plaintext (§7, §7.1)

**Files:**
- Modify:
  - `src/core/ntx_session_pe.c` (`sp_plaintext_fallback` `:64-83`);
  - `src/core/ntx_session_bt_hs.c` (`sp_bths_try` `:180`, `sp_build_bt_handshake` `:92`);
  - `src/core/ntx_session_peer.c` (`ntx_session_peer_step` `:1230-1243`);
  - zliczanie `tts_in_ok` przy promocji połączenia przychodzącego.
- Test: `test/t_pe_strict.c`; dostosowanie `test/t_wire_hs.c` i innych testów zakładających natychmiastową odpowiedź (znajdź je przez `rg "plaintext" test/`)

**Interfaces:**
- Consumes: `s->tts_enc_strict[ti]` (ustawiany przez A5).
- Produces:
  - przychodzący plaintext (`peer_outbound[pi] == 0`) nie wysyła niczego do odebrania 68 B i dopasowania hasha;
  - po dopasowaniu: slot ścisły daje `sp_drop(…, "plaintext_strict_share")` bez wysyłki, pozostałe sloty dostają handshake **dopasowanego** slotu;
  - `sp_build_bt_handshake` nie wybiera już „pierwszego żywego slotu”: przy `peer_tts < 0` zwraca `m[0] = 0`;
  - wychodzący plaintext do slotu ścisłego jest zrywany;
  - `tts_in_ok[ti]++` przy promocji połączenia przychodzącego do `PH_OK`.

- [ ] **Step 1: Napisz test `t_pe_strict.c`** na parze gniazd jak w `t_wire_hs.c`:
  - przychodzący `\x13BitTorrent protocol` + 8 B reserved i nic więcej: po 3 tickach `peer_out_len == 0`;
  - pełne 68 B z nieznanym hashem: zerwanie, 0 B wysłanych;
  - 68 B z hashem slotu publicznego przy `compat_peers = 1`: odpowiedź 68 B z **tym** hashem (nie pierwszego slotu, bo w sesji są dwa sloty);
  - 68 B z hashem slotu ścisłego: zerwanie, 0 B wysłanych, także przy `compat_peers = 1`;
  - wychodzące połączenie do slotu ścisłego z odpowiedzią plaintext: zerwanie;
  - MSE do slotu ścisłego: przechodzi do `PH_OK`, a `tts_in_ok` = 1.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_pe_strict.c`. Oczekiwane: FAIL na pierwszej asercji, bo dziś wysyłamy od razu.
- [ ] **Step 3: Analiza wpływu.** `impact` dla `sp_plaintext_fallback`, `sp_bths_try`, `sp_build_bt_handshake` i `ntx_session_peer_step`.
- [ ] **Step 4: Zaimplementuj.** `sp_plaintext_fallback` wysyła handshake tylko dla `peer_outbound[pi]`. Dla przychodzących handshake idzie z `sp_bths_try` po `sp_match_tts`, gdy `s->peer_plain[pi]`.
- [ ] **Step 5: Dostosuj istniejące testy** do nowej kolejności bajtów. Asercje zmieniamy, nie wyłączamy (§12).
- [ ] **Step 6: Uruchom testy.** `RUN test/t_pe_strict.c`, `RUN test/t_wire_hs.c`, `RUN test/t_utp_bt_handshake.c`, potem `flock … make test TEST_BIN=.t_B.tmp`. Oczekiwane: `PASS` i `ALL PASS`.
- [ ] **Step 7: Commit** `fix(pe): answer inbound plaintext only after the initiator hash; strict MSE for shares`.

### Task B3: Piny trackerów udostępniania w puli, bez TOFU (§6.1)

**Files:**
- Modify: `src/proto/ntx_https_pin.c` (`ntx_https_pin_lookup` `:375`), `src/proto/ntx_http.c` (`http_get_range_tls` `:195-233`)
- Test: `test/t_share_pins.c`

**Interfaces:**
- Produces:
  - `ntx_https_pin_lookup` po wbudowanej puli przeszukuje `ntx_share_tracker_get(i)` (dokładne dopasowanie hosta);
  - host z listy nigdy nie trafia do TOFU (`ntx_https_tofu_note` zwraca −1 dla takiego hosta, a lookup nie sięga do pliku TOFU);
  - `ntx_http_get`/`ntx_http_get_range` zwracają `NTX_HTTP_E_PIN`, gdy `ntx_https_handshake_fd` zwraca −2.

- [ ] **Step 1: Napisz test `t_share_pins.c`.**
  - `ntx_share_trackers_test_set` z hostem `trk.example` i pinem P.
  - `ntx_https_pin_lookup("trk.example", 443, …)` daje `npins == 1` i pin == P, także po `ntx_https_tofu_set_enabled(1)` i `ntx_https_tofu_test_add("trk.example", Q, …)`.
  - `ntx_https_tofu_note("trk.example", Q) == -1`.
  - `ntx_https_tofu_test_events` nie zawiera `trk.example`.
  - Lokalny serwer TLS z testów HTTPS z innym kluczem: `ntx_http_get("https://127.0.0.1:<port>/announce?…")` zwraca `NTX_HTTP_E_PIN`. Wzoruj się na istniejącym teście pinów HTTPS (`rg -l pin test/t_https*.c`).
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_share_pins.c`. Oczekiwane: FAIL.
- [ ] **Step 3: Analiza wpływu i implementacja.** `impact` dla `ntx_https_pin_lookup`, `ntx_https_tofu_note` i `http_get_range_tls`, potem implementacja.
- [ ] **Step 4: Uruchom testy.** `RUN test/t_share_pins.c` oraz wszystkie `test/t_https*.c`. Oczekiwane: `PASS`.
- [ ] **Step 5: Commit** `feat(https): share tracker pins in the pool, never TOFU, pin failure surfaced`.

### Task B4: Kodek PCP i NAT-PMP (§8)

**Files:**
- Create: `src/proto/ntx_pcp.h`, `src/proto/ntx_pcp.c` (zastępują zaślepkę), `test/scripts/pcp_vectors.py`, `test/vectors/pcp/*.bin` + `*.meta.json`
- Test: `test/t_pcp.c`

**Interfaces:**
- Produces:

```c
#define NTX_PCP_PORT 5351
enum { NTX_PCP_PROTO_TCP = 6, NTX_PCP_PROTO_UDP = 17 };
/* RFC 6887 MAP request (60 B): client ip as v4-mapped v6, nonce 12 B, proto, internal/suggested port */
size_t pcp_build_map(uint8_t out[60], const uint8_t client_ip16[16], const uint8_t nonce[12],
                     uint8_t proto, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime);
typedef struct { uint8_t result; uint32_t lifetime, epoch; uint16_t ext_port; uint8_t ext_ip16[16]; } ntx_pcp_map_resp;
/* 0 ok; -1 short/garbage; -2 nonce/proto/port mismatch; 1 = version mismatch (NAT-PMP fallback) */
int pcp_parse_map(const uint8_t *b, size_t n, const uint8_t nonce[12], uint8_t proto, uint16_t int_port,
                  ntx_pcp_map_resp *r);
/* RFC 6886: external address request (2 B) and mapping request (12 B) */
size_t natpmp_build_addr(uint8_t out[2]);
size_t natpmp_build_map(uint8_t out[12], uint8_t op /*1 udp, 2 tcp*/, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime);
int natpmp_parse_addr(const uint8_t *b, size_t n, uint8_t ext_ip[4]);
int natpmp_parse_map(const uint8_t *b, size_t n, uint8_t op, uint16_t int_port, uint16_t *ext_port, uint32_t *lifetime);
int pcp_ip_is_cgnat_or_private(const uint8_t ip16[16]); /* 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7 */
```

- [ ] **Step 1: Napisz generator wektorów `pcp_vectors.py`.** Pakuje struktury z RFC 6887 §7.1/§11.1 i RFC 6886 §3.2/§3.3: żądanie MAP, odpowiedź MAP z innym portem zewnętrznym, odpowiedzi z kodem `UNSUPP_VERSION` (1), z innym nonce, ucięta do 59 B, oraz żądania i odpowiedzi NAT-PMP. Uruchom: `python3 test/scripts/pcp_vectors.py`.
- [ ] **Step 2: Napisz test `t_pcp.c`.**
  - Builder daje bajty identyczne z wektorami.
  - Parser zwraca 0 i `ext_port` z wektora dla poprawnej odpowiedzi, −2 dla złego nonce, −1 dla 59 B, 1 dla `UNSUPP_VERSION`.
  - NAT-PMP: adres i port z wektorów.
  - CGNAT: 100.64.0.1 → 1, 100.128.0.1 → 0, 8.8.8.8 → 0.
- [ ] **Step 3: Uruchom test i sprawdź, że pada.** `RUN test/t_pcp.c`. Oczekiwane: błąd kompilacji.
- [ ] **Step 4: Zaimplementuj** kodek czysto: bez gniazd i stanu.
- [ ] **Step 5: Uruchom test.** `RUN test/t_pcp.c`. Oczekiwane: `PASS`.
- [ ] **Step 6: Commit** `feat(pcp): PCP MAP and NAT-PMP codec with strict parsing`.

### Task B5: Sterownik mapowania portu w sesji (§8)

**Files:**
- Modify: `src/core/ntx_session_portmap.c` (zastępuje zaślepkę)
- Test: `test/t_portmap.c`

**Interfaces:**
- Consumes: B4, `ntx_netx_add`/`ntx_netx_del`, `ntx_rand_bytes`, `cfg->port_map`, `cfg->proxy`, `cfg->tunnel`, `cfg->utp`.
- Produces: implementacja API z `ntx_session_portmap.h` (zad. 1) oraz hooki testowe:

```c
void ntx_portmap_test_set_route_files(const char *v4, const char *v6); /* default /proc/net/route, /proc/net/ipv6_route */
void ntx_portmap_test_set_gateway_port(uint16_t port);                 /* default 5351 */
void ntx_portmap_test_advance_ms(uint64_t ms);                         /* retry and renew clock */
```

Zachowanie:

- `want(on)`: włączone, gdy `on && cfg->port_map >= 0` albo gdy `cfg->port_map == 1`. **Nigdy** przy proxy ani tunelu (stan `OFF`).
- Brama z pliku tras. Własne gniazdo UDP z `connect()` do brama:5351. Każdy datagram dodatkowo sprawdzany przez `recvfrom`: źródło musi być równe bramie i portowi.
- Najpierw PCP. Przy odpowiedzi 1 z parsera przejście na NAT-PMP.
- Ponowienia: 250 ms, potem podwajane, maksymalnie 9 prób na zapytanie (RFC 6887 §8.1.1, z twardym limitem). Po wyczerpaniu stan `NONE`.
- Lifetime 7200 s, odnowienie po połowie przyznanego czasu. Mapowanie TCP zawsze, UDP przy `cfg->utp`.
- Adres zewnętrzny z `pcp_ip_is_cgnat_or_private` daje stan `CGNAT` i jedno ostrzeżenie „port mapping will not help: the ISP uses CGNAT”.
- Publiczny adres na interfejsie domyślnej trasy oznacza brak mapowania (`OFF`).
- `stop()`: lifetime 0 dla każdego aktywnego mapowania, z limitem ≤ 1 s, w ramach 3-sekundowego budżetu zamykania.
- `adv_port`: port zewnętrzny TCP w stanie `ACTIVE`.

- [ ] **Step 1: Napisz test `t_portmap.c`.** Atrapa bramy na 127.0.0.1 ze zmienionym portem, plik tras w `test/.scratch` wskazujący 127.0.0.1. Przypadki:
  - odpowiedź z portem zewnętrznym 40123: stan `ACTIVE`, `ntx_session_adv_port == 40123`, atrapa trackera UDP na loopback (jak w `t_session_trk_udp.c`) odbiera announce z polem port = 40123, a pole `p` w ext-handshake (bufor wyjściowy peera, jak w B1) = 40123;
  - odpowiedź z innego portu źródłowego: ignorowana;
  - zły nonce: ignorowany;
  - brak odpowiedzi: po wyczerpaniu prób `NONE`;
  - `UNSUPP_VERSION`, a potem NAT-PMP: `ACTIVE`;
  - adres 100.64.1.1: `CGNAT`;
  - `ntx_portmap_test_advance_ms(3600000)`: wysłane odnowienie;
  - `stop`: wysłane żądanie z lifetime 0;
  - `cfg.proxy` ustawione: brak jakiegokolwiek datagramu i stan `OFF`.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_portmap.c`. Oczekiwane: FAIL.
- [ ] **Step 3: Zaimplementuj** (pętla `ntx_netx`, bez blokowania).
- [ ] **Step 4: Uruchom test i pełny zestaw.** `RUN test/t_portmap.c`, potem `flock … make test TEST_BIN=.t_B.tmp`. Oczekiwane: `PASS` i `ALL PASS`.
- [ ] **Step 5: Commit** `feat(portmap): PCP/NAT-PMP mapping with external port in announces`.

---

## Strumień C — interfejs, narzędzia, dokumentacja

### Task C1: Flagi CLI, uruchomienie udostępnienia i wypisanie magnetu (§9, §5.4)

**Files:**
- Modify: `src/ntx_main.c` (`parse_args`, `print_usage`, `main`, pętla CLI)
- Test: `test/cli_errors.sh`

**Interfaces:**
- Consumes: `ntx_session_share_add`, `ntx_session_share_poll_event`, `ntx_share_err_msg`, `ntx_share_available`, `cfg.port_map` (zad. 1).
- Produces: zachowanie z §9:
  - opcje `--share=PATH`, `--share-from=FILE`, `--port-map` i `--no-port-map`;
  - po zdarzeniu `ok=1` (tryb CLI): zamknięcie linii statusu (`g_cli_needs_nl`), magnet jako jedna linia na **stdout** i `ntx: shared — <name> (torrent <path>)` na stderr;
  - zdarzenie `ok=0` w trybie CLI, gdy udostępnienie jest jedynym torrentem: komunikat i exit 1;
  - przy `--stats-json` nic surowego nie trafia na stdout: magnet idzie wyłącznie zdarzeniem `share` (C3).

Komunikaty exit 2 (dokładny tekst):
- `ntx: --share cannot be combined with a magnet or .torrent argument`
- `ntx: --share given twice`
- `ntx: --share-from requires --share`
- `ntx: --port-map and --no-port-map are mutually exclusive`
- `ntx: --port-map cannot be used with --proxy or --tunnel (inbound traffic would bypass it and the mapping would reveal your address)`

Przy `!ntx_share_available()` opcje `--share`, `--share-from` i `--port-map` nie pojawiają się w `--help`. Próba użycia `--share` daje exit 1 z komunikatem `ntx_share_err_msg(NTX_SHARE_E_NO_TRACKERS)`.

- [ ] **Step 1: Dopisz przypadki do `test/cli_errors.sh`** (funkcja `expect`):
  - pięć przypadków exit 2 z regexami powyższych komunikatów;
  - exit 1: `--share=$TMP` (katalog), `--share=$TMP/empty.torrent` (pusty), `--share=$TMP/nonexistent`;
  - nazwa z bajtem sterującym (`printf 'x' > "$TMP/$(printf 'a\001b')"`);
  - `--share-from=$TMP/junk.torrent`.

  Każdy z tych przypadków kończy się przed pracą sieciową.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `make ntx && ./test/cli_errors.sh`. Oczekiwane: FAIL na nowych przypadkach.
- [ ] **Step 3: Zaimplementuj.** Najpierw `impact` dla `parse_args` (LOW) i `main`. Ścieżki udostępnienia trzymaj w zmiennych `main`, nie w `ntx_config`.
- [ ] **Step 4: Uruchom test.** `make ntx && ./test/cli_errors.sh`. Oczekiwane: wszystkie `PASS`.
- [ ] **Step 5: Commit** `feat(cli): --share, --share-from, --port-map, --no-port-map`.

### Task C2: Znaczniki linii statusu (§10)

**Files:**
- Modify: `src/ui/ntx_cli.c` (`cli_flags_compact` `:84`, faza w `:183-190`)
- Test: `test/t_cli_tags.c`

**Interfaces:**
- Consumes: pola `ntx_tts_stat.priv`, `share`, `enc_strict`, `trk_pin_fail` i `in_ok`, `phase == "hash"`, `ntx_stats.port_map`, `ext_port` (zad. 1).
- Produces:
  - znaczniki dopisywane na końcu w kolejności: `prv`, `shr`/`shr!`, `enc!`, `pin!N` (gdy N > 0), `map:<port>`/`map-`/`map!cg` (gdy `port_map` ≠ 0), `inN` (dla `share` ≠ 0);
  - faza wyświetlana jako `@hash`;
  - linia ≤ `CLI_MAX_LINE` (176). Przy braku miejsca znaczniki są obcinane od końca listy.

- [ ] **Step 1: Napisz test `t_cli_tags.c`** (dołącza `src/ui/ntx_cli.c`, wynik do `fmemopen`). Statystyka z `priv = 1`, `share = 1`, `enc_strict = 1`, `trk_pin_fail = 2`, `port_map = 2`, `ext_port = 40123`, `in_ok = 3`: linia zawiera kolejno `prv shr enc! pin!2 map:40123 in3`. Dalej: `share = 2` daje `shr!`; `port_map = 4` daje `map!cg`; `port_map = 3` daje `map-`; faza `hash` daje `@hash`. Przy wszystkich licznikach na maksimum (wzorzec z komentarza `:14`) `strlen(line) <= 176`.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** `RUN test/t_cli_tags.c`. Oczekiwane: FAIL.
- [ ] **Step 3: Zaimplementuj.** Najpierw `impact` dla `cli_flags_compact`.
- [ ] **Step 4: Uruchom testy.** `RUN test/t_cli_tags.c` oraz istniejące testy CLI (`rg -l ntx_cli.c test/`). Oczekiwane: `PASS`.
- [ ] **Step 5: Commit** `feat(ui): status tags for private, share, strict, pins, port map`.

### Task C3: JSON API: komenda `share`, zdarzenia, pola, limit magnet (§11)

**Files:**
- Modify:
  - `src/ui/ntx_ipc.h` (`NTX_CMD_SHARE`, `NTX_IPC_E_NO_TRACKERS`, pole `char torrent[NTX_IPC_ARGS_MAX]`, `has_torrent`, `#define NTX_IPC_MAGNET_MAX 2048`, pole `magnet` o rozmiarze `NTX_IPC_MAGNET_MAX + 1`);
  - `src/ui/ntx_ipc.c` (parser `:235-311`, `caps` `:62`, `cmd` `:192`);
  - `src/ui/ntx_ipc_dispatch.c`, `src/ui/ntx_stats.c` (`ntx_stats_to_json`);
  - `src/ntx_main.c` (emisja zdarzeń `share` z osobnego bufora 8 KiB po dispatchu, przed snapshotem).
- Test: `test/t_ipc_ctrl.c`, `test/interop/ipc/assert_ipc.py`, `test/interop/ipc/interop_ipc.sh`

**Interfaces:**
- Consumes: API `ntx_share.h`, pola stats (zad. 1).
- Produces (dokładne kształty z §11):
  - ack `{"type":"ack","seq":N,"cmd":"share","i":K,"ok":1,"state":4}`;
  - błędy synchroniczne `bad_arg`/`io`/`full`/`no_trackers`;
  - zdarzenie `{"type":"share","i":K,"ok":1,"ih":"…","ih2":"…","name":"…","magnet":"…","torrent":"…"}` albo `{"type":"share","i":K,"ok":0,"code":"…"}`;
  - pola torrenta `priv`, `share`, `enc_strict`, `trk_pin_fail` i `in_ok`, pola sesji `port_map` i `ext_port`;
  - `"share"` w `caps` tylko przy `ntx_share_available()`;
  - `magnet` w `add` do 2048 B, `path`/`torrent` ≤ 511 B.

- [ ] **Step 1: Dopisz testy w `t_ipc_ctrl.c`.**
  - Parse `{"cmd":"share","path":"/x","torrent":"/y.torrent","seq":3}` daje `cmd == NTX_CMD_SHARE`, `has_torrent`, `pre == NTX_IPC_OK`.
  - Pusty `path` daje `bad_arg`. `path` o długości 512 B daje `io`.
  - `add` z magnetem 2000 B daje `pre == NTX_IPC_OK`, a 2049 B daje `io`.
  - `caps` zawiera `"share"` dokładnie wtedy, gdy `ntx_share_available()` (oba warianty przez `ntx_share_trackers_test_set`).
  - `ntx_stats_to_json` zawiera `"priv":1,"share":1,"enc_strict":1,"trk_pin_fail":0,"in_ok":0` oraz `"port_map":2,"ext_port":40123`.
  - Escapowanie `name` z `"` i `\n` w zdarzeniu.
- [ ] **Step 2: Rozszerz `assert_ipc.py`** (wartość `CAPS` warunkowa wobec builda) i `interop_ipc.sh`. Scenariusz: `share` nieistniejącego pliku daje `err` `io`, a `share` katalogu daje `io`.
- [ ] **Step 3: Uruchom testy i sprawdź, że padają.** `RUN test/t_ipc_ctrl.c`, potem `make test-ipc`. Oczekiwane: FAIL.
- [ ] **Step 4: Zaimplementuj.** Najpierw `impact` dla `ntx_ipc_parse`, `ntx_ipc_dispatch` (UNKNOWN, potwierdź `rg`), `ntx_stats_to_json` (UNKNOWN, potwierdź `rg`) i `ntx_ipc_hello_json`.
- [ ] **Step 5: Uruchom testy.** `RUN test/t_ipc_ctrl.c`, potem `make test-ipc`. Oczekiwane: `PASS`.
- [ ] **Step 6: Commit** `feat(json): share command, share events, stats fields, 2048 B magnet`.

### Task C4: `make pins-check` / `pins-update`, brama wydania, build testowy (§6.2, §12)

**Files:**
- Create: `scripts/pins/pins.py` (python3 + `openssl`), `scripts/pins/README.md`
- Modify:
  - `Makefile`: cele `pins-check`, `pins-update` i `ntx-sharetest` (`-DNTX_SHARE_TRACKERS_INC='"…"'`, wynik `ntx-sharetest`, dopisany do `.gitignore` i `clean`);
  - `.github/workflows/release.yml`: krok `make pins-check` przed buildem oraz krok sprawdzający, że binarka wydania nie zawiera łańcucha `NTX-TEST-TRACKERS`;
  - `src/proto/ntx_share_trackers.c` **nie jest zmieniany ręcznie**. Wyjątkiem są poprawki przez `pins-update` wykonywane przez opiekuna.

**Interfaces:**
- Produces:
  - `scripts/pins/pins.py check|update [--offline-fixture DIR]`. Kody wyjścia: 0 = OK albo tylko ostrzeżenia; 1 = blokada z tabeli §6.2. Format raportu: `<host> <OK|NEW-KEY|WEBPKI-FAIL|FULL-SCRAPE|UNREACHABLE> <detail>`.
  - `update` zachowuje stary pin, dopisuje nowy w wolne miejsce (przy 4 zajętych usuwa najstarszy), przepisuje blok danych w `ntx_share_trackers.c` i `pins.txt`, po czym wypisuje diff.
  - Build testowy: wariant danych z `NTX_SHARE_TRACKERS_INC` dodaje do binarki łańcuch `NTX-TEST-TRACKERS` i wypisuje go na stderr przy starcie.

- [ ] **Step 1: Napisz test offline.** `--offline-fixture test/vectors/pins/` z zapisanymi wynikami `openssl` dla przypadków: zgodny pin, nowy klucz, błąd WebPKI, pełny scrape, timeout, mniej niż 2 hosty. Oczekiwane kody: 0, 1, 1, 1, 0 (z ostrzeżeniem), 1. Uruchomienie: `python3 scripts/pins/pins.py check --offline-fixture test/vectors/pins/<case>`. Wywołanie dodaj do `test/cli_errors.sh` albo nowego `test/pins_tool.sh` uruchamianego z `make test-cli`.
- [ ] **Step 2: Uruchom test i sprawdź, że pada.** Oczekiwane: FAIL, skryptu jeszcze nie ma.
- [ ] **Step 3: Zaimplementuj** skrypt, cele `Makefile` i kroki `release.yml`. Połączenia mają do 3 prób na host (§6.2).
- [ ] **Step 4: Uruchom testy.** Test offline, potem `make ntx-sharetest && strings ntx-sharetest | grep -q NTX-TEST-TRACKERS && ! strings ntx | grep -q NTX-TEST-TRACKERS`. Oczekiwane: `PASS` i kod 0.
- [ ] **Step 5: Commit** `build(pins): pins-check/pins-update, release gate, share test build`.

### Task C5: Dokumentacja (§12)

**Files:**
- Modify: `docs/cli.md`, `docs/json-api.md` (w tym „Security”: kto pisze na stdin, ten może udostępnić każdy czytelny plik), `docs/protocol.md` (BEP 27, tryb ścisły, §7.1, sól, ograniczenie magnetu przed metadanymi), `docs/storage.md`, `docs/network.md` (pula, procedura kluczy obok „Pin rotation (DoH pool)”, okres ważności binarki, NAT-PMP/PCP), `docs/roadmap.md`, `docs/testing.md`, `README.md`, `CHANGELOG.md`, `SECURITY.md`

**Interfaces:**
- Consumes: dokładne nazwy flag, komunikatów, znaczników, kodów i pól z C1–C4, A5 i B5.

- [ ] **Step 1: Uzupełnij dokumenty** zgodnie z listą §12. W `docs/roadmap.md`:
  - usuń „Torrent creation”, „Private torrents” i część NAT-PMP/PCP z „NAT traversal”;
  - dopisz udostępnianie katalogów, UPnP-IGD i trwały stan udostępnień.
- [ ] **Step 2: Sprawdź spójność.** Każda flaga z `./ntx --help` występuje w `docs/cli.md`, a każdy kod błędu z `ntx_share_err_code` w `docs/json-api.md`: `for k in bad_arg io full no_trackers too_big exists changed; do grep -q "\"$k\"" docs/json-api.md || echo MISSING $k; done`. Oczekiwane: brak wyniku.
- [ ] **Step 3: Commit** `docs: private share, strict encryption, pins, port mapping`.

---

## Integracja

### Task I1: Test end-to-end i interop (§12)

**Files:**
- Create: `test/interop/share/tracker_https.py` (tracker HTTPS: `http.server` + `ssl`, certyfikat P-256 generowany przy starcie, pamięta peerów per hash, odpowiada `compact=1`, `/scrape` bez `info_hash` zwraca 400), `test/interop/share/share_e2e.sh`, `test/interop/share/trackers.inc.in`
- Modify: `Makefile` (cel `test-share`), `test/interop/v2/` (scenariusz qBittorrent z `.torrent` i wymuszonym szyfrowaniem)

**Interfaces:**
- Consumes: wszystko powyżej. Build `ntx-sharetest` z wpisem `https://127.0.0.1:<port>/announce` i pinem SPKI wyliczonym z wygenerowanego certyfikatu.

- [ ] **Step 1: Napisz `share_e2e.sh`.** Uruchamia tracker, potem `ntx-sharetest --share=<plik 5 MiB> --allow-local-peers --store-dir=A > magnet.txt`. Czeka na linię w `magnet.txt` (≤ 60 s). Następnie `ntx-sharetest --allow-local-peers --store-dir=B magnet.txt` do `complete`. Sprawdza:
  - `cmp` pliku źródłowego i pobranego;
  - log trackera: dwa różne peery dla hasha, zero zapytań `/scrape` bez hasha;
  - `ntx --verbose`: zero linii `dht` i `pex` dla tego hasha;
  - `.torrent` w A ma tryb `0600`;
  - plik źródłowy ma niezmienione `mtime`;
  - drugi seed zainicjowany plaintextem (`hs_capture.py` z `test/interop/v2`) jest zrywany bez odpowiedzi.
- [ ] **Step 2: Uruchom test.** `make test-share`. Oczekiwane: `PASS share_e2e`.
- [ ] **Step 3: Scenariusz qBittorrent.** W `test/interop/v2` dodaj przypadek: qBittorrent z `encryption=1` (wymuszone) pobiera przez `.torrent` z A. Uruchom: `make test-interop`. Oczekiwane: pełne pobranie i zgodność bajtów.
- [ ] **Step 4: Commit** `test(share): end-to-end private share over a pinned HTTPS tracker and qBittorrent interop`.

### Task I2: Bramy końcowe i nadzór GitNexus

- [ ] **Step 1: Uruchom wszystkie bramy.** `make ntx && make size && flock /tmp/ntx-maketest.lock make test && make test-cli && make test-ipc && make test-net && make test-share`. Oczekiwane: wszystkie zielone, rozmiar < 1 MiB.
- [ ] **Step 2: Bramka funkcji.** Zbuduj z pustą listą (`make ntx-sharetest` z pustym `trackers.inc`). Oczekiwane: brak `--share` w `--help`, brak `"share"` w `caps`, a `--share=x` daje exit 1 z komunikatem `no_trackers`.
- [ ] **Step 3: Analiza całości.** `detect_changes({repo:"ntx", scope:"compare", base_ref:"main"})` względem commita sprzed zadania 0. Sprawdź, że zmienione procesy CRITICAL (`trk_is_dead`, `data_check_torrent_done`) obejmują tylko hunk z zadania 1 i odczyty pól. `trk_is_dead` ma pozostać niezmieniony.
- [ ] **Step 4: Reindeks.** Koordynator prosi partnera o `gitnexus analyze` i sprawdza `list_repos` (lastCommit = HEAD) oraz `check({repo:"ntx"})`.
- [ ] **Step 5: CI.** Push na gałąź i zielone CI: x86_64, aarch64, riscv64 pod qemu. `make pins-check` w `release.yml` przechodzi z listą z zadania 0.

---

## Self-review (2026-11-08)

Przeczytany projekt §1–§14 względem tego planu:

| Wymaganie projektu | Zadanie |
|---|---|
| §4 BEP 27 + niezerowe `private` | B1, A2 |
| §5.1 store RO / `O_RDONLY` | A1, A5 |
| §5.2 hybryda, sól `ntx salt`, `private`=1, rozmiar kawałka | A3 |
| §5.3 hash w ticku, faza `hash` | A5, zad. 1 (`stats_fill_phase`) |
| §5.4 magnet, `.torrent` 0600, stdout | A4, C1 |
| §5.5 gotowość, revival trackerów, ratio, `changed` | A5, A6 |
| §5.6 `--share-from` | A6 |
| §6 badanie / piny / `pins-check` / minimum 2 | 0, B3, C4 |
| §7 / §7.1 ścisłe MSE + inbound plaintext | B2 |
| §8 NAT-PMP/PCP | B4, B5 |
| §9–§11 CLI / UI / JSON | C1–C3 |
| §12 testy i docs | A*, B*, C*, I1, C5 |
| §13 trzy strumienie + kontrakt | 0 → 1 → A∥B∥C → I |

Luki domknięte w planie: `NTX_HTTP_E_PIN`, `ntx_share_test_advance_ms` / `ntx_portmap_test_advance_ms`, rozłączne `.t_X.tmp` + `flock`, alias GitNexus `ntx`. Budżet hashowania na tick (`NTX_SHARE_HASH_BUDGET_MS 20`), kolejność znaczników statusu i język `pins.py` są ustalone w zadaniach (nie zostawione otwarte).

## Execution

Metoda ustalona z partnerem: **subagent-driven**, trzy równoległe strumienie A/B/C po zadaniach 0 i 1.

REQUIRED SUB-SKILL przy starcie implementacji: `superpowers:subagent-driven-development`.

Kolejność dyspozycji: Task 0 → Task 1 → równolegle A1…A6, B1…B5, C1…C5 → I1 → I2.

Przed pierwszym zadaniem partner potwierdza ten plan. Po potwierdzeniu nie zmieniać kontraktu z zadania 1 bez aktualizacji projektu.
