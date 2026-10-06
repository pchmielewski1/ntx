# ntx documentation

These documents are versioned together with the code. **The code in `src/` is the source of
truth**: if a document and the code disagree, the document is wrong, and a fix or an issue is
welcome.

| Document | Contents |
|----------|----------|
| [architecture.md](architecture.md) | Goals, data flow, the event loop |
| [cli.md](cli.md) | Command-line options, the status line, session phases |
| [json-api.md](json-api.md) | `--stats-json` NDJSON status stream and stdin control commands |
| [protocol.md](protocol.md) | Peer wire, MSE/PE, magnet links, trackers, DHT, PEX, web seeds, BEP 52 |
| [network.md](network.md) | Sockets and event loop, proxy and tunnel, DoH, TLS 1.3 / 1.2, uTP |
| [storage.md](storage.md) | On-disk layout, verification and resume, seeding, session limits |
| [testing.md](testing.md) | `make` test targets and what each suite covers |
| [fuzzing.md](fuzzing.md) | libFuzzer harnesses and the crypto-change policy |
| [module-map.md](module-map.md) | Every source file under `src/` and its responsibility |
| [releasing.md](releasing.md) | How a release is built and published (binaries, `.deb`) |
| [roadmap.md](roadmap.md) | Ideas and known gaps; nothing there is promised |

Outside this directory:

- [`../README.md`](../README.md): overview, build, usage, limitations.
- [`../SECURITY.md`](../SECURITY.md): security status, review findings, how to report a vulnerability.
- [`../CHANGELOG.md`](../CHANGELOG.md): release notes.
