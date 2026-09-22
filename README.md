# 02 - Asenkron Port Scanner and Banner Grabber

## Amac

Verilen IP adresi (veya ana bilgisayar adi) ve port araligini hizlica tarayan, acik portlardan banner (servis tanitim metni) toplayan ve sonucu tablo veya JSON olarak veren arac. Ayni arac C (thread havuzu), C++ (thread havuzu, RAII), Rust (tokio + spawn_blocking) ve C# (async/await) ile yazilir. Ana amac senkron, cok izlekli ve asenkron I/O modellerinin farkini gormektir.

Durum: dort dil de tamamlandi, derleniyor, testleri geciyor ve olcumleri alindi.

## Guvenlik ve hukuki sinir

Yalnizca kendi makinende (`127.0.0.1`), kendi agindaki cihazlarda veya acikca izin verilen hedeflerde kullanilir. Aracin hedefi yerel/ozel ag degilse (RFC1918, loopback, link-local disinda) uyari yazdirilir ve `--yes-i-own-this` bayragi istenir; bayrak verilmezse arac taramayi reddedip cikis kodu 1 ile sonlanir. Bu davranis dort dilde de canli test edilmistir (asagida).

## Komut satiri sozlesmesi (tum diller)

```
portscan <hedef> [--ports 1-1024|22,80,443] [--timeout <ms>] [--concurrency <n>] [--banner] [--format table|json] [--yes-i-own-this]
```

Varsayilanlar: `--ports 1-1024`, `--timeout 800`, `--concurrency 500`, `--format table`. `--timeout` 50-60000 ms, `--concurrency` 1-10000 araliginda olmalidir. Cikis kodlari: 0 tarama bitti, 1 gecersiz arguman veya izin reddi, 2 hedef cozumlenemedi.

Ornek cikti (tablo):
```
PORT    STATE         MS  BANNER
--------------------------------------------------------
135     open           1
445     open           1

scanned 9 ports on 127.0.0.1 (127.0.0.1) in 412 ms: 2 open, 7 closed, 0 filtered
```

Ornek cikti (JSON):
```
{"target":"127.0.0.1","address":"127.0.0.1","scanned":50,"open":[],"closed":50,"filtered":0,"errors":0,"elapsed_ms":2}
```

## Dosya sayisi ve dosya yapisi

Toplam 59 dosya: 2 proje dokumani, 1 olcum betigi, 56 dil dosyasi (C 15, C++ 16, Rust 9, C# 9, artik dosyalar dahil).

```
02-port-scanner/
  README.md
  edu.md
  bench.ps1                  (dort ikiliyi olcen PowerShell betigi)
  c/                          (14 dosya)
    Makefile                 (GNU make, Linux)
    build.bat                (MSVC, Windows; "build.bat test" testleri de calistirir)
    src/main.c               (arguman akisi, tarama akisi, izin kontrolu)
    src/args.c / args.h
    src/ports.c / ports.h    (port araligi ayristirici)
    src/net.h                (ortak platform arayuzu)
    src/net_addr.c           (adres cozumleme, yerel/ozel ag tespiti)
    src/net_sock.c           (soket: connect, poll/select, SIO_TCP_INITIAL_RTO)
    src/scan.c / scan.h      (tek port tarama, banner)
    src/pool.c / pool.h      (sabit boyutlu thread havuzu)
    src/report.c / report.h (tablo ve JSON cikti)
    tests/test_ports.c       (port araligi + arguman testleri)
    tests/test_scan.c        (gercek loopback dinleyicisiyle ag testleri)
    tests/test_report.c
  cpp/                        (15 dosya)
    CMakeLists.txt
    src/main.cpp
    src/Args.hpp / Args.cpp
    src/Ports.hpp / Ports.cpp
    src/Socket.hpp           (ortak arayuz, UniqueSocket RAII)
    src/WinSocket.cpp / LinuxSocket.cpp
    src/Scanner.hpp / Scanner.cpp
    src/Report.hpp / Report.cpp
    tests/test_ports.cpp
    tests/test_scan.cpp
    tests/test_report.cpp
  rust/                       (9 dosya)
    Cargo.toml / Cargo.lock
    src/lib.rs
    src/main.rs
    src/cli.rs
    src/ports.rs
    src/local.rs              (yerel/ozel ag tespiti)
    src/scanner.rs            (socket2 + spawn_blocking, bkz. asagida)
    src/report.rs
    src/error.rs
    tests/scan_test.rs
  csharp/                     (8 dosya)
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

Ilk planlamadan farklar ve nedenleri:
- C'de tek `net.c` yerine `net_addr.c` (adres/DNS) ve `net_sock.c` (soket/connect/poll) ayrildi; her dosya tek bir sorumluluk tasisin diye.
- C++'ta `Socket.hpp` platform-bagimsiz arayuzu tanimlar, `WinSocket.cpp`/`LinuxSocket.cpp` onu uygular; C'deki ayrimla birebir eslesir.
- Rust'ta ozel bir `banner.rs` yazilmadi; banner mantigi `scanner.rs` icinde kaldi cunku connect ve banner okuma ayrilamayacak kadar ic ice (asagida acilaniyor).
- C#'ta `PortRange.cs` planlanan `Args.cs` port ayristirmasindan ayrildi, testlerin port mantigini bagimsiz dogrulayabilmesi icin. Ayrica `LocalAddress.cs` eklendi.

## Mimari

Katmanlar (dort dilde ayni):
1. Girdi: arguman ayristirma, hedef cozumleme (DNS/literal), port listesi uretimi (`1-1024`, `22,80,443` bicimleri, tekrarlar elenir, sirali kume).
2. Tarama cekirdegi: her port icin `connect` denemesi, zaman asimi, `open`/`closed`/`filtered`/`error` sinifi.
3. Banner katmani: acik porta baglanildiktan sonra en fazla 1024 bayt okunur; HTTP portlarinda (`80/8000/8080/8888`) once `HEAD / HTTP/1.0` gonderilir.
4. Rapor: tablo (yalnizca acik portlar listelenir) veya JSON (`open` dizisi + `closed`/`filtered`/`errors` sayaclari).

Es zamanlilik modeli (dile gore degisen tek katman):
- **C:** sabit boyutlu thread havuzu (`pool.c`, `--concurrency` ile sinirli, ust sinir 512), is dagitimi atomik sayacla (`InterlockedIncrement` / `__atomic_fetch_add`). Zaman asimi: non-blocking soket + `select` (Windows) / `poll` (Linux).
- **C++:** `std::jthread` havuzu, is dagitimi `std::atomic<size_t>` ile; `scanPorts` fonksiyonu esiktir. `UniqueSocket` RAII ile handle/fd otomatik kapanir.
- **Rust:** `tokio::spawn` + `Semaphore` gorev sayisini sinirlar, ama asil TCP baglantisi `tokio::task::spawn_blocking` icinde **senkron** `socket2::Socket::connect_timeout` ile yapilir (nedeni asagida "Windows SYN retransmisyonu" bolumunde).
- **C#:** `Task.Run` + `SemaphoreSlim` ile es zamanlilik siniri; `Socket.ConnectAsync` + `CancellationTokenSource(timeout)`.

## Windows SYN retransmisyonu: dort dilde ayni sorun, dort farkli cozum

Bu proje calisirken karsilasilan en onemli teknik sorun buydu ve dort dilin hepsini etkiledi. Windows, reddedilen bir TCP baglantisinda bile (RST hemen donse dahi) varsayilan olarak yaklasik 2 saniyelik bir SYN yeniden gonderim (retransmission) dongusune girer -- **loopback'te bile**. Bu, 1024 portluk bir taramayi dakikalar suren bir isleme cevirir.

Cozum, `mstcpip.h` icindeki `SIO_TCP_INITIAL_RTO` soket kontrolu ile `MaxSynRetransmissions` alanini `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` yapmaktir. Bu sabitin gercek degeri **`(UCHAR)-2` yani `0xFE`**'dir (Windows SDK `mstcpip.h`, satir 314) -- `0xFF` degil. Bu ayrim onemlidir: `0xFF` aslinda `TCP_INITIAL_RTO_UNSPECIFIED_MAX_SYN_RETRANSMISSIONS` sabitidir ve "sistem varsayilanini kullan" anlamina gelir, yani tam olarak kacinilmak istenen 2 saniyelik gecikmeyi geri getirir.

- **C ve C++:** gercek `mstcpip.h` basligindaki adlandirilmis sabiti kullandiklari icin dogru degeri otomatik aldilar; ilk denemede calisti.
- **Rust:** `windows-sys` crate'i bu sabiti disa aktarmiyor (yalnizca ham `WSAIoctl` cagrisini saglar), bu yuzden deger elle yazildi ve ilk seferde yanlislikla `0xFF` yazildi. Sonuc: testler 168 saniye surdu ve kapali portlar `Filtered` olarak raporlandi. `mstcpip.h` dogrudan okunarak `0xFE` oldugu dogrulandi ve duzeltildi (testler 0.26 saniyeye dustu).
- **C#:** ayni sabit `Socket.IOControl` ile elle bayt dizisi olarak gonderilir; dogru deger (`0xFE`) PowerShell ile onceden deneysel olarak dogrulanip kullanildi.

**Rust'ta ikinci bir surpriz:** dogru sabitle bile `tokio::net::TcpStream::connect` (tokio'nun kendi async connect'i, Windows'ta IOCP/AFD tabanli mio arka ucunu kullanir) hicbir zaman "hazir" bildirimi almadi -- baglanti ne basarili ne basarisiz oldu, yalnizca bizim kendi zaman asimimiz (2000 ms) devreye girip `Filtered` dondurdu. Ayni sorun, elle olusturulan soketi `TcpStream::from_std` ile tokio'ya devrettigimizde de tekrarlandi. Kanit: C, C++ ve elle yazilmis bir PowerShell/.NET denemesi ayni ioctl ile 0-30 ms'de basarili oldu; yalnizca tokio'nun IOCP tabanli async connect'i bu sinyali gormedi. Cozum: gercek TCP islemini (`connect` + `poll`/`select`) C ve C++'taki gibi **senkron** yapip `tokio::task::spawn_blocking` icine almak; es zamanlilik sinirini tokio'nun blocking thread havuzu (`max_blocking_threads`, `--concurrency` ile eslenir) uzerinden korumak. Bu, "async calisma zamani her zaman en dogru arac degildir" dersinin somut bir ornegidir.

## Islem yaparken dikkat edilecekler

Genel:
- Isletim sisteminin acik dosya/soket sinirina dikkat: Linux'ta `ulimit -n` (varsayilan 1024), Windows'ta ephemeral port araligi. `--concurrency` bu sinirdan kucuk tutulmalidir; C ve C++ 512 ust siniri kendileri uygular.
- Zaman asimi olmadan `connect` cagrilmaz; filtrelenmis (firewall) portlar baglantiyi bekletir, gercek zaman asimi ile `filtered` olarak isaretlenir.
- Port durumlari dort tanedir: `open`, `closed` (RST/reddedildi), `filtered` (zaman asimi veya erisim engeli), `error` (siniflandirilamayan). Yalnizca acik portlar tabloya yazilir; kapali ve filtrelenmis olanlar yalnizca ozet sayaclarda gorunur.
- Soketler her yolda kapatilmalidir; C `goto`suz erken donuslerle, C++ `UniqueSocket` yikicisiyla, Rust `Drop` ile (socket2 + std TcpStream), C# `using` ile saglar.
- C'de Windows icin `WSAStartup` bir kez cagrilir, program sonunda `WSACleanup`. Linux'ta gerek yoktur.
- Non-blocking soket hazirlik kontrolunde `SO_ERROR` okunmalidir; sadece yazilabilir olmasi baglantinin basarili oldugunu garanti etmez (C, C++, Rust'in blocking connect_timeout'u bunu kendi icinde yapar).
- Banner okumada kesik veri gelebilir; okunan bayt sayisi kadar isle. Yazdirmadan once yazdirilamayan baytlar `.` ile degistirilir (dort dilde ayni algoritma: `sanitize_banner` / `SanitizeBanner` / `scan_sanitize_banner`).
- IPv6 icin `getaddrinfo` (C/C++) veya dilin kendi cozumleyicisi kullanilir; sabit IPv4 varsayilmaz. Yerel/ozel ag testi hem IPv4 hem IPv6 (`::1`, `fe80::/10`, `fd00::/8`, `::ffff:` eslemeli adresler) icin ayni kurallarla calisir.

## Dil karsilastirma tablosu (olculen degerler)

Olcum ortami: Windows 10 Pro 19045, x64, MSVC 14.51, rustc 1.95.0, .NET 10.0.400. Hedef `127.0.0.1`, 7 kosudan ilki atilip 6 kosunun ortalamasi (`bench.ps1`).

| Konu | C | C++ | Rust | C# |
|---|---|---|---|---|
| Es zamanlilik birimi | OS thread havuzu (~512 ust sinir) | OS thread havuzu (`jthread`, ~512 ust sinir) | Async gorev + blocking havuz (`spawn_blocking`) | Task (thread havuzu) |
| Baglanti mekanizmasi | non-blocking connect + `select`/`poll` | ayni, RAII ile | senkron `socket2::connect_timeout` (bkz. yukarida) | `Socket.ConnectAsync` + `CancellationToken` |
| Veri yarisi korumasi | atomik sayac (is dagitimi) | `std::atomic<size_t>` | derleyici (`Send`/`Sync`) + `Semaphore` | `SemaphoreSlim` |
| Windows RTO duzeltmesi | `mstcpip.h` sabiti (otomatik dogru) | `mstcpip.h` sabiti (otomatik dogru) | elle `0xFE` (ilk denemede `0xFF` yazilip duzeltildi) | elle `0xFE` (PowerShell ile onceden dogrulandi) |
| Kaynak satiri (test dahil) | 1085 | 1006 | 733 | 799 |
| Ikili boyut (release) | 156.0 KB | 254.5 KB | 461.0 KB | 158.5 KB apphost + dll |
| 1024 port, localhost, calisma suresi (ortalama) | 49.4 ms | 47.8 ms | 61.8 ms | 161.2 ms |
| 1024 port, localhost, calisma suresi (en iyi) | 37.4 ms | 44.3 ms | 31.0 ms | 93.9 ms |
| 65535 port, timeout 500 ms, calisma suresi | 528 ms | 548 ms | 708.6 ms | 1082.1 ms |
| Tepe RAM (1024 port tarama) | 10.7 MB | 9.2 MB | 12.8 MB | 31.2 MB |
| Tepe RAM (65535 port tarama) | 20.6 MB | 18.0 MB | 41.1 MB | 71.9 MB |
| Bellek guvenligi | Programci sorumlu | RAII ile buyuk olcude | Derleyici garantisi | GC + managed |

Acik port sayisi (135, 445 gibi Windows servisleri) olcumler arasinda 22-25 arasinda degisti; fark dil hatasi degil, tarama anindaki canli sistem durumudur (gecici portlarin acilip kapanmasi) -- ayni ikili art arda calistirildiginda tutarli sonuc verir (22, tekrar kontrol edildi).

Tablodaki degerlerin okunmasi:
- C ve C++ yine en hizli ve en az bellek kullanan surumler; C++ RAII'nin bedeli olcum gurultusu seviyesinde.
- Rust'in en iyi kosusu (31 ms) C'den bile hizli, ama ortalamasi (61.8 ms) daha yuksektir: `spawn_blocking` gorevlerinin tokio'nun blocking havuzuna alinmasi degisken bir zamanlama ek yuku getirir. 65535 portluk buyuk taramada bu fark daha belirgindir.
- C#'in yavasligi (161 ms / 1082 ms) buyuk olcude `Socket.ConnectAsync(EndPoint, CancellationToken)` overload'unun her cagrida bir `CancellationTokenSource` ve Task durum makinesi kurmasindan gelir; JIT ve runtime baslatma maliyeti de ilk turlerde eklenir.
- Rust'in ikili boyutu en buyuk (461 KB): `tokio` calisma zamaninin tamami statik olarak baglanir; buna karsilik en az kaynak satirina (733) sahiptir.

## Gelistirme asamalari

1. Tek IP ve tek port icin baglanti kur, sonucu yazdir.
2. Port araligi ayristirma ve sirali (tek thread) tarama.
3. Zaman asimi ve `open/closed/filtered` ayrimi; Windows SYN retransmisyon sorununun kesfi ve duzeltmesi.
4. Es zamanlilik: thread havuzu / async gorevler; es zamanlilik siniri.
5. Banner toplama (1024 bayt okuma, HTTP icin istek gonderme).
6. Rapor: tablo ve JSON. Test ve karsilastirmali olcum.

## Test ve dogrulama

```
C (Windows):   cd c && .\build.bat test
C (Linux):     cd c && make test          (bellek kontrolu: make asan)
C++:           ctest --test-dir cpp\build -C Release --output-on-failure
Rust:          cd rust && cargo test && cargo clippy --all-targets -- -D warnings
C#:            cd csharp && dotnet test -c Release
```

Son kosu sonuclari: C 3 test ikilisi de gecti (port ayristirma, gercek loopback ag testleri, rapor), C++ 3 test hedefi de gecti, Rust 13 test 0.26 saniyede gecti (`clippy -D warnings` temiz), C# 55 test 93 ms'de gecti. C ve C++ `/W4 /WX` (MSVC) ile 0 uyari, C# `TreatWarningsAsErrors` ile 0 uyari.

Kapsanan durumlar:
- Port araligi ayristirma: tekil port, aralik, virgullu liste, cakisan araliklar, tekrar eleme, sinir degerler (1, 65535), 16 farkli gecersiz girdi (bos, 0, 65536, ters aralik, harf, bosluklu, asiri buyuk sayi).
- Arguman ayristirma: varsayilanlar, tam komut satiri, eksik deger, sinir disi `--timeout`/`--concurrency`, gecersiz `--format`, `--help`.
- Yerel/ozel ag tespiti: 11 yerel ornek (IPv4 ozel araliklari, loopback, link-local, IPv6 loopback/link-local/ULA/IPv4-mapped) ve 7 uzak ornek.
- Banner temizleme: kontrol karakterlerinin `.` ile degistirilmesi, bas/son bosluk temizligi, 120 karakter siniri, bos girdi.
- Canli ag testleri: gercek bir loopback dinleyicisi acilip acik/kapali port ayrimi dogrulanir, banner gercekten okunur, 200 portluk bir aralik 20 kez tekrar taranip sonuc kumesinin degismedigi dogrulanir (yaris/sizinti testi).
- JSON ciktisi: alan sirasi, kacis karakterleri (`"`, `\`), yalnizca acik portlarin `open` dizisinde yer almasi.

Elle dogrulanan izin akisi (Windows):
```
portscan.exe 127.0.0.1 --ports 20-25,80,135,445 --timeout 400 --banner   -> basarili, cikis 0
portscan.exe 8.8.8.8 --ports 80                                         -> izin reddi, cikis 1
```

Olcum: `pwsh .\bench.ps1` (varsayilan 7 kosu, ilki atilir, `-Ports`/`-Timeout`/`-Concurrency` ile ozellestirilebilir).

## Derleme ve calistirma

```
C:      cd c    && make                (Linux)   veya   .\build.bat        (Windows)
C++:    cd cpp  && cmake -S . -B build && cmake --build build --config Release
Rust:   cd rust && cargo build --release
C#:     cd csharp && dotnet build -c Release
```

Calistirma ornekleri:
```
c\build\portscan.exe 127.0.0.1 --ports 1-1024 --banner
cpp\build\Release\portscan.exe scanme.nmap.org --ports 22,80 --yes-i-own-this
rust\target\release\portscan.exe 127.0.0.1 --format json --concurrency 200
csharp\src\PortScan\bin\Release\net10.0\portscan.exe 127.0.0.1 --ports 1-65535 --timeout 500
```

## Kabul olcutleri

| Olcut | Durum |
|---|---|
| Dort dil ayni portlari ayni durumla raporluyor | tamam (canli sistem farki disinda, bkz. tablo notu) |
| Es zamanlilik siniri asilmiyor | tamam, semaphore/havuz ile sinirlanir |
| JSON ciktisi gecerli | tamam, testlerde dogrulandi |
| Izin kontrolu (yerel olmayan hedef) | tamam, dort dilde canli test edildi |
| 65535 port taramasinda soket/handle sizintisi yok | tamam, 20 tekrarli test ile dogrulandi (200 port araliginda); tam 65535 port taramasi tek seferlik olcumle dogrulandi |
| Derleyici uyarisi yok | tamam (`/W4 /WX`, `-Wall -Wextra -Werror`, `clippy -D warnings`, `TreatWarningsAsErrors`) |
| Karsilastirma tablosu gercek olcumlerle dolduruldu | tamam |
| edu.md tamamlandi | tamam |
