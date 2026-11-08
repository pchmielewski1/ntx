# ntx — prywatne udostępnianie pliku (`--share`) — design

Data: 2026-11-08 · Branch: `main` · Status: **projekt, czeka na akceptację partnera**

Dokument dla wykonawców (planowanie i implementacja). Kod nie powstaje w tym kroku.
Oznaczenia: **[partner]** = decyzja partnera, **[moja decyzja]** = decyzja projektanta
(partner może ją zmienić), **[wykonawca]** = świadomie zostawione budującemu.

## 1. Intencja i dlaczego

Partner chce wskazać `ntx` plik i dostać link, którym przekaże ten plik wybranym osobom.
`ntx` ma policzyć metadane torrenta, ogłosić się na trackerach, seedować i wypisać link
magnet, gdy udostępnienie jest gotowe. To samo ma działać przez kanał JSON (`--stats-json`).

Kluczowe „dlaczego”: plik ma dotrzeć **tylko do osób, którym partner przekaże link
lub plik `.torrent`**. Hash torrenta działa jak klucz dostępu, bo nie da się go zgadnąć
(160 lub 256 bitów). O tym, kto pobierze plik, decydują więc wyłącznie miejsca, przez które
hash mógłby wyciec. Projekt zamyka te drogi środkami **ze standardu BitTorrent**, bez
obejść i półśrodków:

| Droga wycieku hasha lub adresu | Zamknięcie |
|---|---|
| DHT (crawlery, BEP 51) | `private=1` (BEP 27): torrent nigdy nie trafia do DHT |
| PEX i holepunch | `private=1`: brak `ut_pex` i `ut_holepunch` dla tego torrenta |
| Podsłuch announce (HTTP i UDP otwartym tekstem) | wyłącznie trackery **HTTPS** |
| MITM na trackerze | przypięte klucze SPKI, bez TOFU, fail-closed |
| Podsłuch handshake'u peer-wire (hash otwartym tekstem) | wymuszone MSE/PE dla udostępnień, bez fallbacku na plaintext |
| Skaner portów: `ntx` odpowiada na przychodzący plaintext hashem **pierwszego aktywnego slotu** | odpowiedź dopiero po pasującym hashu inicjatora (BEP 3 na to pozwala), §7.1 |
| Pełny scrape publicznego trackera | kryterium przyjęcia trackera na listę (§6.3) |
| Ktoś, kto **już ma** plik, liczy hash i pyta trackery o IP udostępniających | losowa sól w `info` (§5.2) **[partner]** |
| Klient odbiorcy z DHT, który dostał magnet | zalecana dystrybucja pliku `.torrent` (§5.4) |

Dodatkowy zysk: przy tajnym hashu MSE jest odporne na aktywnego pośrednika, bo klucze RC4
wyprowadza się z `SKEY` = info-hash. Atakujący, który nie zna hasha, nie odszyfruje
połączenia. RC4 pozostaje słabym szyfrem; to maksimum, jakie daje standard BitTorrent.

Żeby link był użyteczny, odbiorca musi się połączyć z udostępniającym. Dlatego zakres
obejmuje mapowanie portu na routerze przez NAT-PMP/PCP (§8) **[partner]**.

## 2. Cele, nie-cele, anty-cele

**Cele**
- `ntx --share=PLIK` tworzy torrent hybrydowy v1+v2 z `private=1` i losową solą, zapisuje
  `.torrent`, mapuje port na routerze, ogłasza się na przypiętych trackerach HTTPS,
  seeduje i wypisuje magnet na stdout.
- `ntx --share=PLIK --share-from=X.torrent` udostępnia ponownie z zapisanego `.torrent`
  z tym samym linkiem (§5.6).
- Komenda JSON `share` robi to samo w trybie `--stats-json`, z osobnym zdarzeniem
  „gotowe” zawierającym magnet.
- Obsługa BEP 27 dla **każdego** torrenta z flagą `private`, także pobieranego (§4) **[partner]**.
- Wymuszone szyfrowanie **tylko dla udostępnień** (§7) **[partner]**.
- Wkompilowana lista trackerów HTTPS z przypiętymi kluczami, utrzymywana w repozytorium
  i sprawdzana przed wydaniem (§6) **[partner]**.
- Mapowanie portu NAT-PMP (RFC 6886) i PCP (RFC 6887) (§8) **[partner]**.
- Obecny interfejs bez zmian; udostępnianie dodaje tylko flagi, oznaczenia i pola **[partner]**.

**Nie-cele (pierwsza wersja)**
- Udostępnianie katalogów i wielu plików naraz **[moja decyzja]**: partner mówił o pliku;
  katalogi trafiają na roadmapę.
- Trackery podawane przez użytkownika (`--tracker=`) **[moja decyzja]**: lista jest
  „na sztywno” **[partner]**, a furtka obok przypiętej listy osłabiłaby gwarancje.
- UPnP-IGD (SSDP, XML, SOAP), LSD, własny tracker w `ntx`, przechodzenie przez CGNAT.
- Zapisywanie stanu udostępnień między uruchomieniami.

**Anty-cele (porażka, nawet jeśli „działa”)**
- Hash udostępnianego torrenta trafia do DHT, PEX, na tracker spoza listy albo do
  skanera portów.
- Połączenie peer-wire udostępnianego torrenta przechodzi otwartym tekstem.
- `ntx` modyfikuje, skraca, rozszerza albo tworzy udostępniany plik.
- Klucz trackera przyjęty bez weryfikacji (TOFU w kliencie albo na maszynie budującej).
- `ntx` mapuje port przy `--proxy` albo `--tunnel` albo przyjmuje odpowiedź NAT-PMP/PCP
  od kogoś innego niż brama.
- `make` wymaga internetu.
- Zmiana kontraktu istniejącego CLI i JSON (nowe klucze i komendy są dozwolone, `v` zostaje 1).
- Wydanie z `--share` bez zakwalifikowanych trackerów (§6.4) **[partner]**.

## 3. Stan obecny (rekonesans kodu)

| Obszar | Stan | Konsekwencja |
|---|---|---|
| Tworzenie metainfo | brak (`docs/roadmap.md`: „ntx only reads metainfo”) | nowy moduł |
| SHA-1, SHA-256, Merkle | są (`src/crypto/ntx_sha1.c`, `ntx_sha256.c`, `src/core/ntx_merkle.c`) | wykorzystać |
| Bencode | parser **i koder** (`ntx_be_encode`, `be_dict_*` w `src/proto/ntx_bencode.h`) | wykorzystać |
| Magnet | tylko parser (`ntx_magnet_parse`) | nowy generator |
| Store | `open_part()` (`src/core/ntx_store.c:30-58`) otwiera `O_RDWR`, robi `ftruncate` i `mkdir_p_parent` | tryb tylko-do-odczytu |
| `ntx_torrent_set_metainfo` | nie tylko waliduje: robi `mkdir` i otwiera `<store>/<name>` do zapisu (`ntx_torrent.c:218-276`, `:493`, `:511-531`) | rozdzielić walidację od otwarcia store (§5.2) |
| Limit parsera bencode | 1 MiB na **każdy łańcuch** (`ntx_bencode.c:131`, wywołanie w `ntx_session.c:225`) | wiążą `pieces` (20 B/kawałek) i wartości `piece layers` (32 B/kawałek) |
| Serwowanie BEP 9 | działa w obie strony (`t->info_raw`) | wykorzystać |
| Serwowanie hashy BEP 52 (wiadomości 21, 22, 23) | jest (`sp_serve_hash_request`) | wykorzystać |
| Kompletny torrent przy starcie | `pre_complete=1` i **zero announce** (`ntx_session_data_verify_tick`, `data_check_torrent_done`; test `t3d`) | udostępnienie wysyła `started` z `left=0` |
| Martwy tracker | po `NTX_TRK_MAX_FAIL` (3) błędach pomijany do końca życia torrenta (`trk_is_dead`, `ntx_session_trk.c:32-36`) | ponawianie dla udostępnień (§5.5) |
| DHT | lookup tylko dla magnetów (`ntx_session.c:171`), announce po pobraniu (`ntx_session_data.c:402`) | bramka `private` |
| PEX | oferowany zawsze (`ntx_session_peer.c` ok. 1349, `ntx_session_pex.c`) | bramka `private` |
| Holepunch BEP 55 | z `--utp` (`ntx_session_peer.c` ok. 1345) | bramka `private` |
| Flaga `private` | nieczytana (roadmapa: „do not use ntx for private trackers”) | parser i polityka |
| MSE/PE | tylko RC4 (`crypto_provide & 0x02`, `src/proto/ntx_pe.c`); fallback plaintext w `sp_plaintext_fallback` przy `cfg.compat_peers`, ustawionym na sztywno w `main()` | tryb ścisły per torrent |
| Przychodzący plaintext | `sp_plaintext_fallback` (`ntx_session_pe.c:64-83`) od razu woła `ntx_session_peer_send_handshake`; `sp_build_bt_handshake` (`ntx_session_bt_hs.c:93-100`) bierze hash pierwszego slotu innego niż `DEAD`, zanim inicjator przyśle swój | **istniejący wyciek hasha**, poprawka w §7.1 |
| Limit ratio | `NTX_SEED_RATIO_NUM = 3` (`data_enter_ratio_done`) | zwolnienie dla udostępnień |
| Klient TLS | sprawdza tylko pin SPKI liścia; brak magazynu CA i walidacji łańcucha (`ntx_tls.c:575-585`) | rotacja klucza wyłącza tracker w już wydanych binarkach (§6.2) |
| Pula pinów HTTPS | `ntx_https_pin_pool` (`src/proto/ntx_https_pin.c`, do 4 kluczy na host, dziś tylko wpis testowy loopback); ma pierwszeństwo przed `--https-pin-file` i TOFU | tu trafiają trackery udostępniania |
| Mapowanie portów | brak (roadmapa: „no UPnP, NAT-PMP/PCP”) | nowy moduł (§8) |
| JSON | komendy `ping,status,hello,add,pause,resume,remove,quit`; `magnet` i `path` ≤ 511 B (`NTX_IPC_ARGS_MAX`); bufor ack 2048 B (`g_ack`) | nowa komenda, większy limit magnet |
| Wydania | każdy push do `main` publikuje wydanie (`.github/workflows/release.yml`) | brama `pins-check` nie może blokować z powodu chwilowej awarii |
| Rozmiar binarki | 413 016 B przy bramie 1 MiB (`make size`) | jest zapas |

**Analiza wpływu (GitNexus).** `AGENTS.md` wymaga `impact` przed każdą edycją. W tej
sesji serwer MCP nie widział repozytorium (`nanotorrent` niezarejestrowane), a
`node .gitnexus/run.cjs impact` nie zwrócił wyniku. Wywołujących ustaliłem
wyszukiwaniem tekstowym, co według `AGENTS.md` nie zastępuje analizy grafu. Dlatego
**[wykonawca] przed edycją uruchamia `impact` dla każdego zmienianego symbolu** (przy
nieaktualnym indeksie najpierw `node .gitnexus/run.cjs analyze --index-only`) i raportuje
ryzyko HIGH/CRITICAL. Szczególnie dla: `open_part`, `ntx_store_open`,
`ntx_store_open_parts`, `ntx_torrent_set_metainfo`, `sp_plaintext_fallback`,
`sp_build_bt_handshake`, `data_check_torrent_done`, `data_ratio_threshold_hit`,
`trk_is_dead`, `ntx_session_trk_announce`, `ntx_ipc_dispatch`, `ntx_ipc_parse`,
`ntx_stats_to_json`, `ntx_cli_status_update`, `parse_args` i budowania ext-handshake w
`ntx_session_peer.c`.

## 4. BEP 27: torrenty prywatne, pobierane i udostępniane [partner]

`ntx` pobiera i udostępnia torrenty prywatne i publiczne. Dla torrenta prywatnego obowiązuje:

1. **Bez DHT:** żadnego `get_peers` ani `announce_peer` dla tego hasha, także z `--dht`.
2. **Bez PEX:** w ext-handshake połączeń tego torrenta nie oferujemy `ut_pex`,
   przychodzące wiadomości PEX ignorujemy i nie wysyłamy własnych.
3. **Bez holepunch:** nie oferujemy `ut_holepunch` i ignorujemy wiadomości `connect`.
4. **Połączenia wychodzące tylko do peerów od trackerów z metainfo.** Połączenia
   przychodzące są dozwolone, bo BEP 27 ogranicza tylko inicjowanie.
5. **Magnet bez metadanych:** prywatność jest nieznana, dopóki `info` nie zostanie pobrane.
   Gdy po złożeniu metadanych okaże się, że torrent jest prywatny:
   - przerwać lookup DHT;
   - zamknąć połączenia wychodzące do adresów, które nie pochodzą od trackera;
   - od tej chwili stosować punkty 1–4.

   To, co poszło do DHT przed pobraniem metadanych, jest znanym ograniczeniem standardu
   i opisujemy je w `docs/protocol.md` (domyślnie `ntx` startuje bez `--dht`).
   **[wykonawca]** sprawdza, czy sesja zapamiętuje źródło adresu peera. Jeśli nie,
   dodaje znacznik źródła: tracker, DHT, PEX, holepunch albo połączenie przychodzące.
6. **UI:** oznaczenie prywatności w linii statusu i polu JSON (§10, §11).

**[moja decyzja]** Każda niezerowa liczba całkowita w `private` oznacza torrent
prywatny. BEP 27 definiuje wartość `1`, a „niezerowa = prywatny” jest bezpieczniejsze, bo
wątpliwy przypadek nigdy nie trafi do DHT. Brak klucza albo inny typ niż liczba oznacza
torrent publiczny. `ntx` sam zawsze zapisuje `private` = `1`.

## 5. Udostępnianie pliku

### 5.1 Wejście i bezpieczeństwo pliku źródłowego [moja decyzja]

- Akceptowany jest tylko **zwykły plik** o rozmiarze > 0. Najpierw
  `open(path, O_RDONLY | O_CLOEXEC)`, potem `fstat` na deskryptorze i warunek `S_ISREG`.
  Sprawdzamy plik już otwarty, więc między sprawdzeniem a otwarciem nie ma wyścigu.
  Dowiązanie symboliczne podane przez użytkownika jest dozwolone, bo liczy się plik
  docelowy.
- Deskryptor jest trzymany przez cały czas udostępniania, a ścieżka nie jest ponownie
  otwierana. Podmiana pliku pod tą samą nazwą nie zmienia więc tego, co serwujemy.
- **Store tylko do odczytu:** nowy wariant store dla udostępnień, zbudowany na tym
  deskryptorze. Nie wywołuje `open(O_RDWR|O_CREAT)`, `ftruncate` ani `mkdir_p_parent`,
  a `ntx_store_write` na nim zwraca błąd.
- **Nazwa w torrencie** = `basename` ścieżki. Musi być poprawnym UTF-8, bez bajtów
  sterujących (< 0x20, 0x7f) i bez `/`. Inaczej błąd z czytelnym komunikatem, nigdy
  cicha zmiana nazwy.

### 5.2 Metainfo [partner + moja decyzja]

- **Format: hybryda v1+v2** (BEP 3 + BEP 52) **[moja decyzja]**. Czytają go zarówno
  klienty v1, jak i v2. Dla jednego pliku BEP 47 nie wymaga plików wypełniających.
- **Losowa sól [partner]:** klucz `ntx salt` w słowniku `info`, wartością jest 32 znaki
  hex z 16 bajtów z `ntx_rng`. Słownik `info` dopuszcza dodatkowe klucze. Każdy klient
  liczy hash z całego słownika i zachowuje nieznane klucze, więc sól zmienia hash, a
  zgodność zostaje. Nazwę klucza wybrałem ja **[moja decyzja]**: nie koliduje z żadnym
  znanym kluczem (`source` ma w trackerach prywatnych inne znaczenie).
- **Słownik `info`** (klucze posortowane bajtowo, jak wymaga bencode): `file tree`
  (`{<name>: {"": {length, pieces root}}}`), `length`, `meta version`=2, `name`,
  `ntx salt`, `piece length`, `pieces` (SHA-1), `private`=1.
- **Poziom główny:** `announce` (pierwszy tracker z listy), `announce-list` (każdy
  tracker w osobnej warstwie), `piece layers` (dla pliku dłuższego niż jeden kawałek),
  `created by` = `ntx/<NTX_VERSION>`, `creation date`.
- **Rozmiar kawałka:** najmniejsza potęga dwójki z zakresu [16 KiB, 64 MiB], przy której
  liczba kawałków ≤ 2048. Jeśli takiej nie ma, 64 MiB. **Odmowa, gdy liczba kawałków
  > 32 768** (plik > 2 TiB przy 64 MiB). Wartość `piece layers` pliku ma 32 B na kawałek,
  a parser `ntx` przyjmuje łańcuchy ≤ 1 MiB (`ntx_bencode.c:131`), więc 32 768 to granica,
  przy której `ntx` wczyta własny `.torrent`.
- **Info-hashe:** v1 = SHA-1(`info`), używany też na łączu, jak dla innych hybryd w
  `ntx`; v2 = SHA-256(`info`).
- **Walidacja tą samą ścieżką co przy pobieraniu.** Wygenerowane `info` i `piece layers`
  przechodzą bramkę hashy, kontrolę hybrydy i kontrolę `piece layers`.
  `ntx_torrent_set_metainfo` łączy dziś walidację z otwarciem store do zapisu, więc
  trzeba je **rozdzielić**:
  - walidacja bez żadnych efektów na dysku;
  - otwarcie store jako osobny krok: pobieranie korzysta ze store'u jak dotychczas,
    udostępnianie ze store'u tylko-do-odczytu z §5.1.

  Wywołanie obecnej funkcji dla udostępnienia utworzyłoby albo obcięło plik
  `<store>/<name>`. Test musi to wykluczyć.

### 5.3 Hashowanie bez blokowania pętli [moja decyzja + wykonawca]

- Hashowanie jest przyrostowe, w ticku sesji, jak dzisiejszy `VERIFY`. Czytamy przez
  deskryptor i jednocześnie liczymy SHA-1 kawałka, SHA-256 liści 16 KiB i drzewo Merkle.
- Budżet na tick dobiera **[wykonawca]**. Ograniczenie: pojedyncza iteracja pętli nie
  może przekroczyć ok. 50 ms, żeby nie zagłodzić sieci i kanału JSON.
- **Faza `hash`**, postęp w `pct`. Torrent ma w tym czasie stan `VERIFY` (4), bez nowej
  wartości stanu, a `ih` to 40 zer do końca hashowania.
- Plik zmieniony w trakcie hashowania (§5.5) przerywa udostępnianie z błędem `changed`.

### 5.4 Wyniki: `.torrent` i magnet [partner + moja decyzja]

- **Plik `.torrent` [partner]:** `<store-dir>/<name>-<pierwsze 8 znaków hex hasha v1>.torrent`.
  Sól daje każdemu udostępnieniu inny hash, więc sufiks zapobiega kolizjom
  **[moja decyzja]**. Zapis jest atomowy: plik tymczasowy w tym samym katalogu, `fsync`,
  `rename`. Tryb `0600`, bo plik jest kluczem dostępu **[moja decyzja]**. Istniejący plik
  o tej nazwie z tym samym hashem jest nadpisywany; z innym hashem daje błąd `exists`.
- **Magnet [partner]:**
  `magnet:?xt=urn:btih:<40 hex>&xt=urn:btmh:1220<64 hex>&dn=<nazwa>&tr=<url>…`
  ze wszystkimi trackerami z listy. `dn` i `tr` są kodowane procentowo (RFC 3986). Test
  round-trip: magnet przechodzi przez `ntx_magnet_parse` i daje te same hashe.
- **CLI:**
  - po osiągnięciu gotowości magnet trafia na **stdout** jako jedna linia;
  - na stderr pojawia się `ntx: shared — <name> (torrent <ścieżka>)`;
  - stdout w trybie CLI dziś nie jest używany, więc `ntx --share=f > link.txt` daje plik,
    który `ntx` przyjmie jako wejście (pierwsza linia = magnet);
  - przed wypisaniem trzeba zamknąć bieżącą linię statusu na terminalu (`g_cli_needs_nl`).
- **Zalecenie w dokumentacji:** odbiorcom spoza `ntx` przekazuj plik `.torrent`. Magnet
  nie niesie flagi `private`, więc klient odbiorcy z włączonym DHT może zapytać DHT o
  hash, zanim pobierze metadane.

### 5.5 Gotowość, seedowanie, zmiany pliku [moja decyzja]

- **„Gotowe”** oznacza, że:
  - hashowanie jest skończone;
  - `.torrent` jest zapisany;
  - mapowanie portu zakończyło się sukcesem, porażką albo zostało pominięte (§8), nigdy
    nie czekamy w nieskończoność;
  - co najmniej jeden przypięty tracker zwrócił poprawną odpowiedź na `event=started`
    z `left=0` i portem zewnętrznym.

  Dopiero wtedy pojawia się magnet w CLI albo zdarzenie `share` w JSON.
- **Trackery udostępnienia nie umierają na stałe.** Po `NTX_TRK_MAX_FAIL` błędach
  następuje ponowna próba po 5 min, a opóźnienie podwaja się do 60 min. Udostępnienie
  uruchomione bez sieci zrobi się gotowe, gdy sieć wróci. **Wyjątek:** tracker odrzucony
  przez niezgodny klucz nie jest ponawiany w tej sesji (fail-closed).
- Po 60 s bez gotowości idzie jedno ostrzeżenie na stderr, a status pokazuje stan
  trackerów (§10). Brak gotowości nie kończy procesu.
- Jeśli **wszystkie** trackery z listy odrzuciły klucz, komunikat mówi wprost: klucze w
  tej wersji `ntx` są nieaktualne albo trwa atak MITM; zaktualizuj `ntx`.
- **Seedowanie:** stan `DONE`, ogłoszenia okresowe i `stopped` przy wyjściu albo `remove`,
  jak dla innych torrentów. **Bez limitu ratio 3.0**, bo autor bywa jedynym pełnym
  źródłem. Limity `NTX_SEED_MAX_OK` i `NTX_SEED_MAX_HS` pozostają.
- **Wykrywanie zmian pliku:**
  - po hashowaniu zapisujemy `st_dev`, `st_ino`, `st_size`, `st_mtim` i `st_ctim`;
  - co sekundę (tick statystyk) robimy `fstat` na deskryptorze;
  - przy różnicy udostępnienie przechodzi w błąd `changed`: choke wszystkich, odrzucanie
    żądań, `stopped` do trackerów, komunikat w UI i JSON;
  - nie ma automatycznego ponownego hashowania.

  Ryzyko szczątkowe: zapis między dwoma `fstat` może wysłać jeden zły blok. Odbiorca
  odrzuci go przy weryfikacji hasha, więc dane nie ulegną uszkodzeniu.

### 5.6 Ponowne udostępnienie z zapisanego `.torrent` [partner + moja decyzja]

Sól sprawia, że każde nowe `--share` daje nowy link. Żeby po restarcie zachować ten sam
link, służy `--share=PLIK --share-from=X.torrent` (w JSON: komenda `share` z kluczem
`torrent`):

1. Wczytać `.torrent` zwykłym parserem. Wymagane:
   - `private` niezerowe;
   - jeden plik;
   - `length` równe rozmiarowi pliku.

   Nazwa pliku na dysku może się różnić; w torrencie zostaje nazwa z `.torrent`.
2. Plik źródłowy otwieramy jak w §5.1, a store jak w §5.2 (tylko do odczytu).
3. **Pełna weryfikacja** wszystkich kawałków (SHA-1 i Merkle) w fazie `hash`. Każda
   niezgodność daje błąd `changed` i torrent nie jest udostępniany.
4. Trackery: zawsze aktualna przypięta lista z binarki. Trackery z `.torrent` spoza listy
   są ignorowane. Lista trackerów nie wchodzi do `info`, więc hash się nie zmienia. Magnet
   jest generowany na nowo z aktualną listą.
5. Dalej jak w §5.5. `.torrent` nie jest przepisywany.

`--share-from` bez `--share` daje błąd. Stan udostępnień nadal nie jest zapisywany
automatycznie (nie-cel).

## 6. Trackery udostępniania i przypięte klucze [partner]

### 6.1 Lista

- Nowa wkompilowana tablica, np. `src/proto/ntx_share_trackers.h`. Każdy wpis to URL
  `https://…/announce`, host, SNI i 1–4 przypięte klucze SPKI (SHA-256 klucza publicznego
  certyfikatu serwera). Te same hosty i klucze trafiają do `ntx_https_pin_pool`, który ma
  pierwszeństwo przed `--https-pin-file` i TOFU.
- **Tylko HTTPS.** UDP i HTTP nie pozwalają wykryć MITM i ujawniają hash.
- **Bez TOFU:** host z puli nigdy nie przechodzi przez TOFU. **[wykonawca]** potwierdza
  to testem, także z włączonym TOFU.
- **Fail-closed:** niezgodny klucz oznacza zerwanie połączenia przed wysłaniem zapytania,
  licznik w statusie i JSON, a tracker nie jest już używany w tej sesji.
- Nagłówek w gicie jest jedynym źródłem prawdy, a `pins.txt` dostaje te same wpisy dla
  audytu. Kompilacja jest offline **[partner]**.
- Udostępnianie zawsze używa całej listy, bez opcji wyboru.

### 6.2 Aktualizacja kluczy: `make pins-check` i `make pins-update` [partner + moja decyzja]

- `make pins-check` dla każdego hosta z listy:
  - pobiera certyfikat i **wymaga pełnej weryfikacji WebPKI na maszynie uruchamiającej**:
    łańcuch do systemowego magazynu CA i zgodność nazwy (`openssl s_client
    -verify_return_error -verify_hostname HOST -servername HOST`);
  - liczy SPKI i porównuje z listą;
  - sprawdza pełny scrape (§6.3).

  Raportuje wynik dla każdego hosta. Kod wyjścia ≠ 0, jeśli coś wymaga uwagi.
- `make pins-update` robi to samo, a dodatkowo:
  - zweryfikowany nowy klucz dopisuje w wolne miejsce, **zachowując stary** (okres
    przejściowy); przy 4 zajętych miejscach usuwa najstarszy;
  - wypisuje diff i aktualizuje `pins.txt`;
  - host z błędem weryfikacji **nie** dostaje klucza.
- Zwykłe `make`, `make test` i przepisy pakietów (Nix, Gentoo, deb, rpm, Alpine, Arch)
  nie łączą się z siecią.
- **Brama wydania.** `release.yml` uruchamia `make pins-check`. Opiekun uruchamia
  `make pins-update`, przegląda diff i commituje **[moja decyzja]**: bez automatycznych
  commitów z CI do łańcucha dostaw. Każdy push do `main` jest wydaniem, więc brama
  rozróżnia przypadki (każde połączenie do 3 prób):

  | Wynik dla hosta | Brama |
  |---|---|
  | klucz zgodny | OK |
  | zweryfikowany nowy klucz, którego nie ma na liście | **blokuje**, trzeba `pins-update` |
  | certyfikat nie przechodzi weryfikacji WebPKI | **blokuje**: możliwy MITM na CI albo zepsuty host; decyduje człowiek |
  | host odpowiada pełnym scrape'em | **blokuje**: tracker trzeba usunąć z listy |
  | host nieosiągalny lub timeout | ostrzeżenie, nie blokuje |
  | mniej zakwalifikowanych hostów niż minimum z §6.4 | **blokuje** |
- **Okres ważności wydanej binarki [partner, konsekwencja].** Klient TLS `ntx` sprawdza
  tylko klucz liścia, więc binarka wydana przed rotacją klucza traci ten tracker. Partner
  to przyjmuje, bo wydania są regularne. Dokumentacja mówi o tym wprost, także w
  kontekście pakietów dystrybucji, które aktualizują się z opóźnieniem. Przypinanie
  klucza urzędu certyfikacji wymagałoby walidacji łańcucha w kliencie TLS i jest poza
  zakresem.
- Procedurę opisujemy w `docs/network.md` obok istniejącej „Pin rotation (DoH pool)”.

### 6.3 Kryteria przyjęcia trackera na listę [moja decyzja]

Tracker trafia na listę tylko wtedy, gdy spełnia wszystkie warunki:

1. Działa po HTTPS **z klientem TLS `ntx`**, sprawdzonym samą binarką `ntx`, nie
   `openssl`.
2. Certyfikat przechodzi weryfikację z §6.2.
3. Przyjmuje announce dla niezarejestrowanego hasha (otwarty tracker) i zwraca peerów
   dla tego hasha.
4. **Nie udostępnia pełnego scrape'a:** `/scrape` bez `info_hash` zwraca błąd albo pustą
   odpowiedź.
5. Preferowany: klucz stabilny między odnowieniami certyfikatu (historia w `pins.txt`).

Operator trackera zawsze widzi hash. Pełną gwarancję daje tylko tracker, któremu ufa się
osobiście.

### 6.4 Pierwsza lista: badanie hostów jako część zadania [partner]

- Zbudowanie pierwszej listy to **pierwsze zadanie planu**, wykonywane przed resztą prac,
  bo jego wynik może zatrzymać funkcję. Kandydatów zbieramy z publicznych list trackerów
  HTTPS i sprawdzamy według §6.3. Wyniki, łącznie z odrzuconymi i powodem odrzucenia,
  trafiają do `docs/network.md`.
- **Minimum to 2 zakwalifikowane trackery [moja decyzja].** Przy jednym trackerze
  pojedyncza rotacja klucza wyłącza udostępnianie we wszystkich wydanych binarkach.
- **Jeśli minimum nie zostanie osiągnięte, funkcji nie wydajemy [partner].** Kod może
  wejść do repozytorium, ale `--share` i komenda `share` są wtedy niedostępne w
  wydaniu: brak w `--help` i `caps`, a próba użycia daje błąd `no_trackers`. Brama z
  §6.2 pilnuje tego automatycznie.

## 7. Wymuszone szyfrowanie: tylko udostępnienia [partner]

- Torrenty udostępniane przez `ntx` (z `--share` i `--share-from`) działają w trybie
  ścisłym:
  - połączenie wychodzące, na które druga strona odpowiada plaintextem, jest zrywane;
  - przychodzący handshake plaintext z hashem udostępnienia jest zrywany bez wysłania
    czegokolwiek (§7.1);
  - MSE przyjmuje wyłącznie RC4, tak jak dziś.
- Pozostałe torrenty, także prywatne pobierane, zachowują dzisiejszy fallback
  (`compat_peers`). Bez nowej flagi CLI. `--compat-peers` zostaje bez zmian.
- Decyzja zapada **per torrent**. Dla połączeń przychodzących torrent jest znany z `SKEY`
  (MSE) albo z hasha inicjatora (plaintext, §7.1).
- Dotyczy TCP, uTP i tunelu NTX1 jednakowo.

### 7.1 Przychodzący plaintext: najpierw hash inicjatora [moja decyzja, wszystkie torrenty]

Dziś `ntx` odpowiada na przychodzące `\x13BitTorrent protocol` własnym handshake'iem z
hashem pierwszego aktywnego slotu, zanim zobaczy hash inicjatora. BEP 3 pozwala odbiorcy,
który obsługuje wiele torrentów, poczekać na handshake inicjatora. Nowe zachowanie:

1. Odebrać pełne 68 B od inicjatora, nie wysyłając niczego.
2. Dopasować hash do slotu, tak jak dziś robi to `sp_match_tts`. Brak dopasowania:
   zerwanie bez wysyłania czegokolwiek.
3. Slot w trybie ścisłym: zerwanie bez wysyłania czegokolwiek.
4. W pozostałych przypadkach: odpowiedź handshake'iem **dopasowanego** slotu.

Poprawka obejmuje wszystkie torrenty, bo usuwa istniejący wyciek: skaner portów nie pozna
już hasha żadnego torrenta. Połączenia wychodzące i MSE (torrent znany z `SKEY`) się nie
zmieniają.

## 8. Mapowanie portu: NAT-PMP i PCP [partner + moja decyzja]

Cel: udostępniający za routerem domowym ma być osiągalny dla odbiorców, bez UPnP.

- **Protokoły:** PCP (RFC 6887, opkod `MAP`, IPv4 i IPv6), a gdy brama odpowie
  niezgodnością wersji, NAT-PMP (RFC 6886, mapowanie TCP i UDP). Mapujemy port TCP
  nasłuchu, a przy `--utp` także UDP.
- **Kiedy działa [moja decyzja]:**
  - **automatycznie**, gdy w sesji jest aktywne udostępnienie;
  - `--no-port-map` wyłącza mapowanie;
  - `--port-map` włącza je także dla sesji bez udostępnienia;
  - **nigdy** przy `--proxy` ani `--tunnel` (anty-cel: ruch przychodzący omijałby proxy,
    a mapowanie ujawniałoby adres).
- **Brama:** domyślna trasa z `/proc/net/route` (IPv4) i `/proc/net/ipv6_route` (IPv6).
  Zapytania idą wyłącznie do bramy, na port 5351.
- **Bezpieczeństwo odpowiedzi:**
  - przyjmujemy tylko datagramy ze źródła = adres bramy i port 5351;
  - dla PCP wymagany jest zgodny 12-bajtowy nonce z `ntx_rng`;
  - ścisłe parsowanie długości i pól, odpowiedzi niepasujące do zapytania są odrzucane;
  - ponowienia zgodne z RFC (wykładnicze opóźnienie), z twardym limitem zapytań.
- **Czas życia:** żądamy 7200 s i odnawiamy po połowie przyznanego czasu. Przy wyjściu i
  przy `remove` ostatniego udostępnienia mapowanie jest usuwane (lifetime 0) w ramach
  istniejącego 3-sekundowego budżetu zamykania.
- **Port zewnętrzny:** brama może przydzielić inny port niż lokalny. Wtedy w announce
  (`port`) i w polu `p` ext-handshake wysyłamy **port zewnętrzny**.
- **Diagnoza bez obejść:**
  - adres zewnętrzny z bramy w zakresie prywatnym albo CGNAT (100.64.0.0/10) oznacza
    ostrzeżenie: „mapowanie nie pomoże, dostawca stosuje CGNAT”;
  - brak odpowiedzi bramy po wyczerpaniu prób oznacza status „brak” i dalsze działanie
    bez mapowania;
  - publiczny adres na interfejsie oznacza brak NAT, więc mapowania nie robimy.
- **Wskaźnik osiągalności [moja decyzja]:** licznik połączeń przychodzących, które przeszły
  handshake. To jedyny rzetelny dowód, że ktoś z zewnątrz do nas dotarł.
- Moduł jest nowy (np. `src/proto/ntx_pcp.c` i `src/core/ntx_session_portmap.c`) i działa na
  istniejącym timerze i pętli `ntx_netx`, nieblokująco. UPnP-IGD zostaje na roadmapie.

## 9. Wiersz poleceń [partner + moja decyzja]

- Nowe opcje zgodne z regułą `--opcja=wartość`:
  - `--share=PATH`;
  - `--share-from=FILE.torrent` (tylko razem z `--share`);
  - `--port-map` i `--no-port-map`.

  Pozostałe istniejące opcje działają bez zmian.
- `--share` jest źródłem torrenta, więc łączenie go z magnetem, `.torrent` albo plikiem z
  linkiem daje exit 2: `ntx: --share cannot be combined with a magnet or .torrent argument`.
  Drugie `--share`, `--share-from` bez `--share` oraz `--port-map` razem z `--no-port-map`
  też dają exit 2. `--port-map` z `--proxy` albo `--tunnel` daje exit 2 z uzasadnieniem,
  jak dzisiejszy komunikat dla `--dht`.
- Exit 1 i komunikat w stylu `docs/cli.md` („Start-up failures”) dają:
  - brak pliku, plik niezwykły, pusty albo nieczytelny;
  - nieprawidłowa nazwa;
  - plik większy niż 2 TiB;
  - brak trackerów;
  - istniejący `.torrent` z innym hashem;
  - `--share-from` niepasujące do pliku.
- `--share` z `--dht` jest dozwolone, ale udostępnienie i tak nie dotyka DHT (§4).
- `--share` z `--stats-json`: magnet nie idzie surowym tekstem na stdout, tylko jako
  zdarzenie JSON (§11).
- Nowe opcje trafiają do `--help` i `print_usage`, chyba że §6.4 je wyłącza.

## 10. Linia statusu (bez zmiany układu) [partner + moja decyzja]

Układ i istniejące pola zostają. Dochodzą:

- faza `@hash` podczas hashowania i weryfikacji `--share-from` (pasek i `pct` pokazują
  postęp);
- `prv` dla każdego prywatnego torrenta;
- `shr` dla udostępnienia, a `shr!` po błędzie `changed`;
- `enc!` dla torrenta w trybie ścisłego szyfrowania;
- `pin!N` = liczba trackerów odrzuconych przez niezgodny klucz (pokazywane, gdy > 0);
- `map:<ext port>`, `map-` (brak mapowania lub brak odpowiedzi bramy), `map!cg`
  (wykryty CGNAT), widoczne, gdy mapowanie jest aktywne;
- `inN` = połączenia przychodzące po handshake'u dla udostępnienia.

Znaczniki dopisujemy na końcu istniejącej listy, w ramach limitu `CLI_MAX_LINE` (176).
Kolejność i obcinanie ustala **[wykonawca]**, a tabela w `docs/cli.md` je dokumentuje.
Podsumowanie przy wyjściu bez zmian (`complete —` dla seedowanego udostępnienia).

## 11. JSON API (`v` pozostaje 1) [partner + moja decyzja]

- `caps` dostaje `"share"`, z wyjątkiem sytuacji z §6.4.
- **Komenda:** `{"cmd":"share","path":"…","torrent":"…","seq":N}`. `torrent` jest
  opcjonalne i odpowiada `--share-from`. Obie ścieżki mają ≤ 511 B, jak w `add`. Nowy
  znany klucz `torrent` jest łańcuchem.
- **Błędy synchroniczne** (`err`):
  - `bad_arg`: brak albo pusta ścieżka;
  - `io`: plik się nie otwiera, nie jest zwykłym plikiem albo jest pusty;
  - `full`: brak wolnego slotu;
  - `no_trackers`: nowy kod.
- **Sukces:** `{"type":"ack","seq":N,"cmd":"share","i":K,"ok":1,"state":4}`, **bez `ih`**,
  bo hash nie jest jeszcze znany.
- **Zdarzenie gotowości** (raz na udostępnienie, osobna linia, osobny bufor ≥ 8 KiB):
  `{"type":"share","i":K,"ok":1,"ih":"<40 hex>","ih2":"<64 hex>","name":"…","magnet":"…","torrent":"<ścieżka>"}`.
- **Zdarzenie błędu:**
  `{"type":"share","i":K,"ok":0,"code":"changed"|"io"|"exists"|"no_trackers"|"too_big"}`.
- **Pola torrenta w `stats`:**
  - `priv` (0/1);
  - `share`: 0 = nie, 1 = aktywne, 2 = błąd;
  - `enc_strict` (0/1);
  - `trk_pin_fail` (liczba);
  - `in_ok`: liczba połączeń przychodzących.

  W fazie `hash` `ih` to 40 zer.
- **Pola sesji w `stats`:**
  - `port_map`: 0 = wyłączone, 1 = trwa, 2 = aktywne, 3 = brak bramy lub brak odpowiedzi,
    4 = CGNAT;
  - `ext_port`.
- **Limit `magnet` w `add`** rośnie z 511 B do co najmniej 2048 B, żeby magnet
  wygenerowany przez `ntx` dało się dodać z powrotem. To złagodzenie, zgodne wstecz.
  Ramka 4096 B zostaje.
- `remove` udostępnienia: `stopped`, zamknięcie deskryptora, usunięcie mapowania, jeśli to
  było ostatnie udostępnienie. Nic na dysku nie jest usuwane, a `.torrent` zostaje.
- Sekcję „Security” w `docs/json-api.md` uzupełniamy: kto pisze na stdin, ten może
  udostępnić każdy plik, który `ntx` potrafi odczytać.

## 12. Testy i kryteria akceptacji [moja decyzja + wykonawca]

- **Jednostkowe:**
  - generator metainfo względem wektorów z `test/scripts/bep52_gen.py`, rozszerzonego o
    `private`, `ntx salt` i hybrydę jednoplikową, ze stałą solą w teście: identyczne
    bajty `info` i hashe;
  - reguła rozmiaru kawałka (granice i odmowa > 32 768);
  - round-trip magnet ↔ `ntx_magnet_parse`;
  - rozdzielona walidacja metainfo nie tworzy ani nie zmienia żadnego pliku;
  - store tylko-do-odczytu odmawia zapisu;
  - wykrywanie zmian (`changed`);
  - `--share-from`: zgodny plik daje ten sam hash, zmieniony bajt daje `changed`;
  - bramki BEP 27: brak `ut_pex` i `ut_holepunch` w ext-handshake, brak wywołań DHT,
    ignorowanie PEX, przejście magnet → private, „niezerowa = prywatny”;
  - tryb ścisły MSE: plaintext przychodzący i wychodzący zrywany, MSE przechodzi,
    torrenty nieudostępniane bez zmian;
  - §7.1: na przychodzący plaintext `ntx` nie wysyła ani bajtu przed handshake'iem
    inicjatora, a nieznany hash daje zero wysłanych bajtów. Istniejące testy, które
    zakładają natychmiastową odpowiedź, trzeba dostosować, a nie wyłączać;
  - ponawianie martwych trackerów udostępnienia i brak ponowień po niezgodnym kluczu;
  - pula pinów bez TOFU;
  - NAT-PMP/PCP: wektory zapytań i odpowiedzi w `test/vectors/`, odrzucenie złego
    źródła, złego nonce i krótkiej odpowiedzi, port zewnętrzny w announce i
    ext-handshake, odnowienie, usunięcie przy wyjściu, wykrycie CGNAT, brak mapowania
    przy `--proxy`/`--tunnel`. Atrapa bramy na loopback z mechanizmem podmiany adresu
    bramy w buildzie testowym wybranym przez **[wykonawca]**.
- **CLI:** `test/cli_errors.sh` dla wszystkich nowych błędów i kodów wyjścia.
- **JSON:** `t_ipc_ctrl.c` i `test/interop/ipc/` dla `share`, kluczy `torrent`, zdarzeń,
  nowych pól, `caps` i limitu magnet.
- **Interop:** `ntx --share` z lokalnym trackerem HTTPS przypiętym testowym wpisem
  (`--allow-local-peers`). Pobierają:
  - drugi `ntx` przez magnet;
  - qBittorrent z `test/interop/v2` przez `.torrent`, z wymuszonym szyfrowaniem po
    stronie qBittorrenta.

  Wymagane: pełne pobranie, zgodność bajtów, zero ruchu DHT i PEX dla tego hasha. Mechanizm
  podmiany listy trackerów w buildzie testowym (np. makro jak `NTX_NO_MAIN`) wybiera
  **[wykonawca]**.
- **Bramy:** `make test`, `make test-cli`, `make test-ipc`, `make size` < 1 MiB i zielone
  CI (x86_64, aarch64, riscv64 pod qemu).
- **Dokumentacja:**
  - `docs/cli.md`, `docs/json-api.md`;
  - `docs/protocol.md`: BEP 27, tryb ścisły, §7.1, sól;
  - `docs/storage.md`: store tylko-do-odczytu, `.torrent`;
  - `docs/network.md`: pula trackerów, wyniki badania, procedura kluczy, NAT-PMP/PCP;
  - `docs/roadmap.md`: usunąć „Torrent creation”, „Private torrents” i część „NAT
    traversal” dotyczącą NAT-PMP/PCP; dopisać katalogi, UPnP i trwały stan udostępnień;
  - `README.md`, `CHANGELOG.md`, `docs/testing.md`, `SECURITY.md` (nowa powierzchnia: PCP
    w LAN).

## 13. Podział pracy dla 3 równoległych wykonawców (wejście do planu)

**Zadanie 0, sekwencyjne, przed strumieniami:** badanie trackerów (§6.4), wykonywane
`ntx` z dostępem do sieci. Wynik to lista kandydatów z pinami i decyzja, czy minimum jest
osiągnięte. Przy porażce partner decyduje, czy kontynuować prace (kod bez wydania funkcji).

**Wspólny kontrakt przed startem strumieni:** nagłówek z API modułu udostępniania; pola
torrenta i sesji (`priv`, `share_state`, `enc_strict`, źródło peera, `ext_port`,
`port_map_state`, `in_ok`); kody błędów; nazwy znaczników.

- **A — rdzeń udostępniania:**
  - generator metainfo (z solą) i magnetu;
  - rozdzielenie walidacji od otwarcia store i store tylko-do-odczytu;
  - hashowanie przyrostowe i `--share-from`;
  - cykl życia: gotowość, `started`/`left=0`, ponawianie trackerów, zwolnienie z ratio,
    `changed`;
  - zapis `.torrent`.

  Pliki: nowe `src/core/ntx_share*.c`, `ntx_store.c`, `ntx_torrent.c`,
  `ntx_session_data.c`, `ntx_session_trk.c`.
- **B — bezpieczeństwo sieci i osiągalność:**
  - BEP 27 (DHT, PEX, holepunch, źródło peera);
  - tryb ścisły MSE;
  - §7.1 (`ntx_session_bt_hs.c`, `ntx_session_pe.c`);
  - pula pinów bez TOFU (`ntx_https_pin.c`, nowy `ntx_share_trackers.h`);
  - moduł NAT-PMP/PCP i port zewnętrzny w announce i ext-handshake.

  Pliki: `ntx_session_peer.c`, `ntx_session_pex.c`, `ntx_session.c`, nowe
  `ntx_pcp.c` i `ntx_session_portmap.c`.
- **C — interfejs, narzędzia, dokumentacja:**
  - `--share`, `--share-from`, `--port-map` i `--no-port-map` w `parse_args`;
  - wypisanie magnetu i znaczniki linii statusu;
  - komenda i zdarzenia JSON, pola `stats`, limit magnet w IPC;
  - `make pins-check`, `make pins-update` (`scripts/pins/`), brama w `release.yml`;
  - testy CLI i IPC oraz wszystkie dokumenty z §12.

  Pliki: `src/ntx_main.c`, `src/ui/*`, `Makefile`, `scripts/pins/`,
  `.github/workflows/release.yml`, `test/cli_errors.sh`, `test/t_ipc_ctrl.c`, `docs/*`.

Integracja i test interop (§12) idą na końcu, po złączeniu strumieni.

## 14. Zostawione wykonawcy

- budżet hashowania na tick;
- kolejność i obcinanie znaczników statusu;
- mechanizmy testowej listy trackerów i testowej bramy;
- sposób oznaczania źródła peera;
- podział na funkcje i pliki w ramach strumieni;
- harmonogram ponowień PCP w granicach RFC;
- język skryptów `pins-*` (sh lub python, zależne tylko od `openssl` i interpretera
  dostępnego w CI).
