# portscan-4lang - Asynchronous Port Scanner and Banner Grabber

The same port scanner, written four times: in C, C++, Rust and C#. All four implement the same command line contract, print the same table and pass the same tests. Then the difference between them is measured.

Status: all four languages are complete, they build, their tests pass and the benchmarks have been taken.

## Purpose

A command line tool that scans a port range on a given IP address or hostname, grabs banners (service identification text) from open ports, and reports the result as a table or JSON. The same tool is written separately in four languages; the goal is to see side by side how the synchronous, thread-based and asynchronous I/O models actually differ.

This repository is the second of a 12-project series in which I solve the same problem in four languages and compare them by measurement rather than by opinion. Each project lives in its own repository. Rules that hold across the series:

- Language comparisons are measured, never guessed; the method and the environment are always stated.
- Errors are never swallowed silently: return codes in C, `std::expected` in C++, `Result` in Rust, exceptions in C#.
- Tests are mandatory; each language uses its own test tooling.
- Compiler warnings are treated as errors (`/W4 /WX`, `-Wall -Wextra -Werror`, `clippy -D warnings`, `TreatWarningsAsErrors`).

## Safety and legal boundary

Use this only against your own machine (`127.0.0.1`), devices on your own network, or targets you have explicit permission to scan. If the resolved target is not a loopback, private (RFC 1918) or link-local address, the tool refuses to scan and exits with code 1 unless `--yes-i-own-this` is passed. This guard is live-tested in all four implementations (see below).

## Command line interface (shared contract for all four languages)

```
portscan <target> [--ports 1-1024|22,80,443] [--timeout <ms>] [--concurrency <n>] [--banner] [--format table|json] [--yes-i-own-this]
```

Defaults: `--ports 1-1024`, `--timeout 800`, `--concurrency 500`, `--format table`. `--timeout` must be between 50 and 60000 ms, `--concurrency` between 1 and 10000. Exit codes: 0 scan finished, 1 invalid argument or refused permission, 2 target could not be resolved.

Table output:

```
PORT    STATE         MS  BANNER
--------------------------------------------------------
135     open           1
445     open           1

scanned 9 ports on 127.0.0.1 (127.0.0.1) in 412 ms: 2 open, 7 closed, 0 filtered
```

JSON output:

```
{"target":"127.0.0.1","address":"127.0.0.1","scanned":50,"open":[],"closed":50,"filtered":0,"errors":0,"elapsed_ms":2}
```

## File count and layout

62 files in total: 1 document, 1 benchmark script, 1 build-all script, 3 repository files and 56 source files (C 19, C++ 16, Rust 11, C# 10).

```
portscan-4lang/
  README.md
  bench.ps1                  (PowerShell script that benchmarks all four binaries)
  buildeverything.bat        (builds and tests all four languages with one command)
  LICENSE
  .gitignore
  .gitattributes
  c/                         (19 files)
    Makefile                 (GNU make, Linux)
    build.bat                (MSVC, Windows; "build.bat test" also runs the tests)
    src/main.c               (argument flow, scan flow, permission guard)
    src/args.c / args.h
    src/ports.c / ports.h    (port range parser)
    src/net.h                (shared platform interface)
    src/net_addr.c           (address resolution, local/private network detection)
    src/net_sock.c           (sockets: connect, poll/select, SIO_TCP_INITIAL_RTO)
    src/scan.c / scan.h      (single-port scan, banner grab)
    src/pool.c / pool.h      (fixed-size thread pool)
    src/report.c / report.h  (table and JSON output)
    tests/test_ports.c       (port range + argument tests)
    tests/test_scan.c        (network tests against a real loopback listener)
    tests/test_report.c
  cpp/                       (16 files)
    CMakeLists.txt
    src/main.cpp
    src/Args.hpp / Args.cpp
    src/Ports.hpp / Ports.cpp
    src/Socket.hpp           (shared interface, UniqueSocket RAII wrapper)
    src/WinSocket.cpp / LinuxSocket.cpp
    src/Scanner.hpp / Scanner.cpp
    src/Report.hpp / Report.cpp
    tests/test_ports.cpp
    tests/test_scan.cpp
    tests/test_report.cpp
  rust/                      (11 files)
    Cargo.toml / Cargo.lock
    src/lib.rs               (module tree; library target needed for integration tests)
    src/main.rs
    src/cli.rs
    src/ports.rs
    src/local.rs             (local/private network detection)
    src/scanner.rs           (socket2 + spawn_blocking, see below)
    src/report.rs
    src/error.rs
    tests/scan_test.rs
  csharp/                    (10 files)
    PortScan.slnx
    src/PortScan/PortScan.csproj
    src/PortScan/Program.cs
    src/PortScan/Args.cs
    src/PortScan/PortRange.cs
    src/PortScan/LocalAddress.cs
    src/PortScan/Scanner.cs
    src/PortScan/Report.cs
    tests/PortScan.Tests/PortScan.Tests.csproj
    tests/PortScan.Tests/PortRangeTests.cs
```

Differences from the original plan and why:
- C splits the network layer into `net_addr.c` (addresses and DNS) and `net_sock.c` (sockets, connect, poll) instead of one `net.c`, so each file carries a single responsibility.
- C++ mirrors that split: `Socket.hpp` declares the platform-independent interface, `WinSocket.cpp` and `LinuxSocket.cpp` implement it.
- Rust has no separate `banner.rs`; banner reading stayed inside `scanner.rs` because connecting and reading are too tightly coupled to separate meaningfully (explained below).
- C# gained `PortRange.cs` (split out of argument parsing so the port logic can be tested on its own) and `LocalAddress.cs`.

## Architecture

The same four layers in every language:

1. **Input:** argument parsing, target resolution (literal IP or DNS), port list generation (`1-1024`, `22,80,443`; duplicates removed, result is a sorted set).
2. **Scan core:** a `connect` attempt per port with a timeout, classified as `open` / `closed` / `filtered` / `error`.
3. **Banner layer:** after connecting, read at most 1024 bytes; on HTTP ports (`80/8000/8080/8888`) send `HEAD / HTTP/1.0` first, because those services wait for a request before saying anything.
4. **Report:** a table (open ports only) or JSON (an `open` array plus `closed`/`filtered`/`errors` counters).

The concurrency model is the only layer that genuinely differs per language:

- **C:** a fixed-size thread pool (`pool.c`, bounded by `--concurrency`, hard cap 512), work handed out through an atomic counter (`InterlockedIncrement` / `__atomic_fetch_add`). Timeouts come from a non-blocking socket plus `select` (Windows) or `poll` (Linux).
- **C++:** a `std::jthread` pool with a `std::atomic<size_t>` work counter; `scanPorts` is the only entry point. `UniqueSocket` closes every handle through RAII.
- **Rust:** `tokio::spawn` plus a `Semaphore` bounds the number of in-flight tasks, but the actual TCP connect runs **synchronously** inside `tokio::task::spawn_blocking` via `socket2::Socket::connect_timeout` — see the next section for why.
- **C#:** `Task.Run` plus `SemaphoreSlim` for the concurrency limit; `Socket.ConnectAsync` with a `CancellationTokenSource(timeout)`.

## Windows SYN retransmission: one problem, four different encounters

This was the single most interesting technical problem in the project, and it hit all four languages. Windows walks through its default SYN retransmission schedule — roughly two seconds — even for a connection that is refused outright, **including on loopback**. That turns a 1024-port scan into a multi-minute job.

The fix is the `SIO_TCP_INITIAL_RTO` socket control from `mstcpip.h`, setting `MaxSynRetransmissions` to `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS`. The real value of that constant is **`(UCHAR)-2`, i.e. `0xFE`** (Windows SDK `mstcpip.h`, line 314) — not `0xFF`. The distinction matters: `0xFF` is `TCP_INITIAL_RTO_UNSPECIFIED_MAX_SYN_RETRANSMISSIONS`, which means "keep the system default" and therefore restores exactly the two-second delay you were trying to avoid.

- **C and C++** use the named constant from the real header, so they got the right value for free and worked on the first try.
- **Rust:** the `windows-sys` crate does not export the constant (only the raw `WSAIoctl` binding), so the value was written by hand — and the first attempt used `0xFF`. The result: the test suite took 168 seconds and closed ports were reported as `Filtered`. Reading `mstcpip.h` directly confirmed `0xFE` and fixed it; the suite then ran in 0.26 seconds.
- **C#** sends the same control through `Socket.IOControl` as a hand-built byte array; the correct value (`0xFE`) was verified experimentally with PowerShell before being written into the code.

**A second surprise in Rust:** even with the right constant, `tokio::net::TcpStream::connect` (tokio's own async connect, which uses the IOCP/AFD-based mio backend on Windows) never produced a readiness signal for a refused connection — it neither succeeded nor failed, and only our own 2000 ms timeout fired, yielding `Filtered`. Handing a manually created socket to tokio via `TcpStream::from_std` behaved the same way. The evidence that this was tokio-specific: C, C++ and a hand-written PowerShell/.NET probe all completed in 0–30 ms with the identical ioctl applied. The fix was to do the real TCP work (`connect` plus `poll`/`select`) synchronously, exactly as C and C++ do, and wrap it in `tokio::task::spawn_blocking`, keeping the concurrency bound through tokio's blocking thread pool (`max_blocking_threads`, matched to `--concurrency`). It is a concrete lesson that an async runtime is not automatically the right tool.

## Things to watch out for

General:
- Mind the OS limit on open sockets and file descriptors: `ulimit -n` on Linux (1024 by default), the ephemeral port range on Windows. `--concurrency` must stay under it; C and C++ additionally enforce a 512 cap of their own.
- Never call `connect` without a timeout; a filtered (firewalled) port will keep the connection pending until the timeout marks it `filtered`.
- There are four port states: `open`, `closed` (RST / refused), `filtered` (timeout or access denied) and `error` (anything that could not be classified). Only open ports are listed in the table; closed and filtered ones appear only in the summary counters.
- Sockets must be closed on every path: C through early returns, C++ through the `UniqueSocket` destructor, Rust through `Drop`, C# through `using`.
- In C, `WSAStartup` is called once on Windows and `WSACleanup` at exit; Linux needs neither.
- On a non-blocking socket, readiness for writing is not proof of a successful connection — `SO_ERROR` must be read (Rust's blocking `connect_timeout` does this internally).
- Banner reads can return partial data; process exactly the number of bytes received. Non-printable bytes are replaced with `.` before printing (the same algorithm in all four: `scan_sanitize_banner` / `sanitizeBanner` / `sanitize_banner` / `SanitizeBanner`).
- Use `getaddrinfo` (C/C++) or the language's own resolver for IPv6; never assume IPv4. The local/private check applies the same rules to IPv4 and IPv6 (`::1`, `fe80::/10`, `fd00::/8` and `::ffff:` mapped addresses).

## Language comparison (measured values)

Environment: Windows 10 Pro 19045, x64, MSVC 14.51, rustc 1.95.0, .NET 10.0.400. Target `127.0.0.1`, average of 6 runs after discarding the first of 7 (`bench.ps1`).

| Topic | C | C++ | Rust | C# |
|---|---|---|---|---|
| Unit of concurrency | OS thread pool (512 cap) | OS thread pool (`jthread`, 512 cap) | async task + blocking pool (`spawn_blocking`) | Task (thread pool) |
| Connect mechanism | non-blocking connect + `select`/`poll` | same, with RAII | synchronous `socket2::connect_timeout` (see above) | `Socket.ConnectAsync` + `CancellationToken` |
| Data-race protection | atomic work counter | `std::atomic<size_t>` | compiler (`Send`/`Sync`) + `Semaphore` | `SemaphoreSlim` |
| Windows RTO fix | `mstcpip.h` constant (correct for free) | `mstcpip.h` constant (correct for free) | hand-written `0xFE` (first attempt `0xFF`, fixed) | hand-written `0xFE` (verified with PowerShell first) |
| Source lines (tests included) | 1085 | 1006 | 733 | 799 |
| Binary size (release) | 156.0 KB | 254.5 KB | 461.0 KB | 158.5 KB apphost + dll |
| 1024 ports, localhost (average) | 49.4 ms | 47.8 ms | 61.8 ms | 161.2 ms |
| 1024 ports, localhost (best) | 37.4 ms | 44.3 ms | 31.0 ms | 93.9 ms |
| 65535 ports, 500 ms timeout | 528 ms | 548 ms | 708.6 ms | 1082.1 ms |
| Peak RAM (1024-port scan) | 10.7 MB | 9.2 MB | 12.8 MB | 31.2 MB |
| Peak RAM (65535-port scan) | 20.6 MB | 18.0 MB | 41.1 MB | 71.9 MB |
| Memory safety | programmer's responsibility | largely handled by RAII | guaranteed by the compiler | GC + managed |

The open-port count (Windows services such as 135 and 445) varied between 22 and 25 across measurements. That is not a language difference but live system state — ephemeral ports opening and closing during the scan. Running the same binary back to back gives a consistent answer (22, re-checked).

How to read these numbers:

1. **C and C++ are again the fastest and the leanest**, and the cost of C++'s RAII is within measurement noise. The price shows up in binary size: 254 KB against 156 KB.
2. **Rust's best run (31 ms) beats C**, but its average (61.8 ms) is higher: handing every scan to tokio's blocking pool adds variable scheduling overhead. The gap widens on the 65535-port scan.
3. **C#'s 161 ms / 1082 ms** comes largely from the `Socket.ConnectAsync(EndPoint, CancellationToken)` overload allocating a `CancellationTokenSource` and a Task state machine per call, plus JIT and runtime startup in the early rounds.
4. **Rust produces the largest binary (461 KB)** because the whole tokio runtime is linked in statically — yet it needs the fewest source lines (733).

## Requirements

| Requirement | Needed for | Note |
|---|---|---|
| Visual Studio Build Tools (MSVC, C++ workload) | C and C++ | ships with `cl` and `cmake` |
| CMake 3.24+ | C++ | the version bundled with Visual Studio works |
| Rust 1.75+ (`rustup`) | Rust | `cargo` and `clippy` |
| .NET SDK 10 | C# | `dotnet` |
| GCC/Clang and GNU make | C and C++ on Linux | not needed on Windows |

## Building and running

To build all four languages with one command, from the repository root:

```
buildeverything.bat            build only
buildeverything.bat test       build and run the tests of all four languages
```

The script locates the MSVC environment itself through `vswhere`, so there is no need to open a Developer Command Prompt. If a toolchain is missing (no `cargo`, for example) that language is skipped and the rest still builds. If any component fails, the exit code is 1.

To build a single language:

```
C (Windows):   cd c && .\build.bat            binary: c\build\portscan.exe
C (Linux):     cd c && make                   binary: c/build/portscan
C++:           cd cpp && cmake -S . -B build && cmake --build build --config Release
Rust:          cd rust && cargo build --release
C#:            cd csharp && dotnet build -c Release
```

The four binaries are interchangeable — same flags, same output, same exit codes:

| Language | Binary |
|---|---|
| C | `c\build\portscan.exe` |
| C++ | `cpp\build\Release\portscan.exe` |
| Rust | `rust\target\release\portscan.exe` |
| C# | `csharp\src\PortScan\bin\Release\net10.0\portscan.exe` |

## Usage examples

All output below is real, captured on the development machine.

### See what is listening on your own machine

```
portscan.exe 127.0.0.1 --ports 1-10000 --timeout 300 --banner
```

```
PORT    STATE         MS  BANNER
--------------------------------------------------------
135     open           0
445     open           0
5040    open           2
5357    open           0
6463    open           0
7768    open           0
9010    open           0
9180    open           0

scanned 10000 ports on 127.0.0.1 (127.0.0.1) in 382 ms: 8 open, 9991 closed, 1 filtered
```

Reading this: ten thousand ports were probed in 382 ms. Eight of them have a program listening. 9991 answered with a TCP RST, which means the machine is up and nothing is bound to that port. One port never answered at all — something (here, the local firewall) dropped the packet silently.

### Find out which program owns a port

The scanner tells you a port is open; `netstat` tells you which process opened it:

```
netstat -ano | findstr ":6463.*LISTENING"
```

```
TCP    127.0.0.1:6463         0.0.0.0:0              LISTENING       24772
```

The last column is the process ID. On the development machine those eight ports turned out to be:

| Port | PID | Process |
|---|---|---|
| 135 | 1104 | svchost.exe (Windows RPC) |
| 445 | 4 | System (SMB file sharing) |
| 5040 | 8848 | svchost.exe |
| 5357 | 4 | System (WSDAPI) |
| 6463 | 24772 | Discord.exe |
| 7768 | 5360 | Spotify.exe |
| 9010 | 25288 | lghub_agent.exe (Logitech G Hub) |
| 9180 | 4300 | lghub_updater.exe |

Discord and Spotify open local API ports so a browser can talk to the desktop app. That is normal. The point of the exercise is that you can now name every open port on your machine — anything you cannot explain is worth investigating.

### Grab a banner from a real service

A banner is the greeting line a service sends on connect. Start a test server in another terminal:

```
python -m http.server 8080
```

Then:

```
portscan.exe 127.0.0.1 --ports 8080 --banner
```

```
PORT    STATE         MS  BANNER
--------------------------------------------------------
8080    open           0  HTTP/1.0 200 OK

scanned 1 ports on 127.0.0.1 (127.0.0.1) in 2 ms: 1 open, 0 closed, 0 filtered
```

Banners identify software and often its exact version, which is what makes them useful in an audit. Scanning the authorized public test host shows why:

```
portscan.exe scanme.nmap.org --ports 21,22,25,80,443 --banner --timeout 3000 --concurrency 50 --yes-i-own-this
```

```
note: scanning a non-local target
PORT    STATE         MS  BANNER
--------------------------------------------------------
21      open          37
22      open          37  SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
25      open          23
80      open          37  HTTP/1.1 200 OK
443     open          48

scanned 5 ports on scanme.nmap.org (45.33.32.156) in 454 ms: 5 open, 0 closed, 0 filtered
```

That one line names the SSH implementation, its version and the distribution it ships with.

Not every service answers. Ports 21, 25 and 443 above are open but stayed silent because they wait for the client to speak first (FTP and SMTP expect a protocol greeting exchange; 443 expects a TLS handshake, not plain text). An empty banner on an open port is normal, not a failure.

### Scan your own router

```
portscan.exe 192.168.1.1 --ports 1-1024,8080,8443 --timeout 1500 --concurrency 100 --banner
```

```
PORT    STATE         MS  BANNER
--------------------------------------------------------
53      open           4                  <- DNS
80      open           4  HTTP/1.1 405    <- management UI (http)
443     open           6                  <- management UI (https)

scanned 1026 ports on 192.168.8.1 (192.168.8.1) in 548 ms: 3 open, 1023 closed, 0 filtered
```

`HTTP/1.1 405` means "method not allowed": the router answered our `HEAD` probe by refusing the method. That is still a useful answer — it proves an HTTP server is there.

A router exposing only DNS and its web UI is healthy. Telnet (23) or FTP (21) open on a router is worth turning off.

### Machine-readable output

```
portscan.exe 127.0.0.1 --ports 1-10000 --timeout 300 --banner --format json
```

```
{"target":"127.0.0.1","address":"127.0.0.1","scanned":2,"open":[{"port":8080,"state":"open","banner":"HTTP/1.0 200 OK","ms":1}],"closed":1,"filtered":0,"errors":0,"elapsed_ms":3}
```

Piping it into PowerShell:

```
$scan = .\portscan.exe 127.0.0.1 --ports 1-10000 --timeout 300 --format json | ConvertFrom-Json
$scan.open | Sort-Object ms -Descending | Format-Table port, ms, banner
```

Or with `jq`:

```
portscan.exe 127.0.0.1 --ports 1-10000 --format json | jq '.open[].port'
```

### What `--concurrency` actually buys you

The same 512-port scan against the same host, only the concurrency changed:

| `--concurrency` | Time |
|---|---|
| 1 | 3254 ms |
| 10 | 285 ms |
| 100 | 62 ms |
| 500 | 63 ms |

Going from 1 to 100 is a 52x speedup. Going from 100 to 500 buys nothing, because at that point the scan is already finished and the bottleneck is no longer waiting on the network. Raising the limit past what the work needs only costs sockets and memory. On a remote target, keep it low (50 or so): a wide, fast scan looks like an attack to an intrusion detection system and strains your own uplink.

### Recipes

| Goal | Flags |
|---|---|
| Quick check of common services | `--ports 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080` |
| Full sweep | `--ports 1-65535 --timeout 500` |
| Look for web servers | `--ports 80,443,8000,8080,8443,3000,5000 --banner` |
| Look for databases | `--ports 1433,3306,5432,6379,27017 --banner` |
| Remote target, be polite | `--timeout 3000 --concurrency 50` |
| Feed another tool | `--format json` |

`--banner` only does extra work on ports that are actually open, so it costs almost nothing on a wide scan. Leave it on.

### Reading the output

Three states, and the difference matters:

- **open** — the connection was established; something is listening there.
- **closed** — the host answered with a TCP RST: the machine is up, that port has nothing on it.
- **filtered** — nothing came back before the timeout. Usually a firewall dropping packets silently, or no host at that address at all.

The table lists open ports only; closed and filtered ones appear as counts in the summary line, otherwise a full sweep would print 65535 rows.

The distinction is visible in timing. Scanning an address with no host on it:

```
portscan.exe 192.168.99.99 --ports 80,443 --timeout 600
```

```
scanned 2 ports on 192.168.99.99 (192.168.99.99) in 601 ms: 0 open, 0 closed, 2 filtered
```

It took the full 600 ms timeout because nothing ever replied. A closed port replies in single-digit milliseconds. That timing difference is how you tell "nothing there" apart from "something is there but this port is shut".

### The four binaries agree

Same scan, all four implementations:

```
=== C ===        135 open, 445 open, 6463 open, 7768 open, 9010 open   -> 5 open, 0 closed, 0 filtered
=== C++ ===      135 open, 445 open, 6463 open, 7768 open, 9010 open   -> 5 open, 0 closed, 0 filtered
=== Rust ===     135 open, 445 open, 6463 open, 7768 open, 9010 open   -> 5 open, 0 closed, 0 filtered
=== C# ===       135 open, 445 open, 6463 open, 7768 open, 9010 open   -> 5 open, 0 closed, 0 filtered
```

Error paths match to the character, including the exit codes:

```
portscan.exe 8.8.8.8 --ports 80
C     exit=1  error: 8.8.8.8 is not a local or private address; pass --yes-i-own-this only if you own it or have permission to scan it
C++   exit=1  error: 8.8.8.8 is not a local or private address; pass --yes-i-own-this only if you own it or have permission to scan it
Rust  exit=1  error: 8.8.8.8 is not a local or private address; pass --yes-i-own-this only if you own it or have permission to scan it
C#    exit=1  error: 8.8.8.8 is not a local or private address; pass --yes-i-own-this only if you own it or have permission to scan it

portscan.exe 127.0.0.1 --ports 100-1
C     exit=1  error: port range start is greater than its end
C++   exit=1  error: port range start is greater than its end
Rust  exit=1  error: port range start is greater than its end
C#    exit=1  error: port range start is greater than its end
```

## Testing and verification

```
C (Windows):   cd c && .\build.bat test
C (Linux):     cd c && make test          (memory check: make asan)
C++:           ctest --test-dir cpp\build -C Release --output-on-failure
Rust:          cd rust && cargo test && cargo clippy --all-targets -- -D warnings
C#:            cd csharp && dotnet test -c Release
```

Latest run: all three C test binaries passed (port parsing, live network tests, reporting), all three C++ test targets passed, 13 Rust tests passed in 0.26 s with `clippy -D warnings` clean, and 55 C# tests passed in 93 ms. C and C++ report 0 warnings under `/W4 /WX`, C# reports 0 warnings under `TreatWarningsAsErrors`.

Covered cases:
- **Port range parsing:** single port, range, comma list, overlapping ranges, duplicate elimination, boundary values (1, 65535) and 16 different invalid inputs (empty, 0, 65536, reversed range, letters, leading space, oversized number).
- **Argument parsing:** defaults, full command line, missing value, out-of-range `--timeout` and `--concurrency`, invalid `--format`, `--help`.
- **Local/private detection:** 11 local samples (IPv4 private ranges, loopback, link-local, IPv6 loopback/link-local/ULA/IPv4-mapped) and 7 remote samples.
- **Banner sanitising:** control bytes replaced with `.`, leading and trailing whitespace trimmed, the 120-character limit, empty input.
- **Live network tests:** a real loopback listener is opened and the open/closed distinction is verified, a banner is genuinely read from a test server, and a 200-port range is rescanned 20 times to confirm the result set does not change (race and leak check).
- **JSON output:** field order, escaping of `"` and `\`, and that only open ports appear in the `open` array.

Permission guard verified manually (Windows):

```
portscan.exe 127.0.0.1 --ports 20-25,80,135,445 --timeout 400 --banner   -> succeeds, exit 0
portscan.exe 8.8.8.8 --ports 80                                          -> refused, exit 1
```

Benchmarking: `pwsh .\bench.ps1` (7 runs by default, the first one discarded; `-Ports`, `-Timeout` and `-Concurrency` can be overridden).

## Development stages

1. Connect to a single IP and port, print the result.
2. Port range parsing and a sequential, single-threaded scan.
3. Timeouts and the `open`/`closed`/`filtered` distinction; discovery and fix of the Windows SYN retransmission problem.
4. Concurrency: thread pool / async tasks, with a concurrency limit.
5. Banner grabbing (1024-byte read, HTTP probe where needed).
6. Reporting: table and JSON. Tests and comparative benchmarks.

## Acceptance criteria

| Criterion | Status |
|---|---|
| All four languages report the same ports with the same state | done (apart from live system variance, see the table note) |
| The concurrency limit is never exceeded | done, enforced by semaphore / thread pool |
| JSON output is valid | done, verified in tests |
| Permission guard for non-local targets | done, live-tested in all four languages |
| No socket or handle leak in a 65535-port scan | done; verified by a 20-round repeat test over a 200-port range, plus a one-shot full 65535-port measurement |
| No compiler warnings | done (`/W4 /WX`, `-Wall -Wextra -Werror`, `clippy -D warnings`, `TreatWarningsAsErrors`) |
| Comparison table filled with real measurements | done |

## License

MIT. See [LICENSE](LICENSE).
