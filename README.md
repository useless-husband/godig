# godig
A DNS resolver and dig-like lookup tool written from scratch in Go: message codec, iterative +trace, and a small caching server.

godig 是一個只用 Go 標準函式庫寫成的 DNS 解析器與查詢工具，用法類似 `dig`。DNS 訊息的編碼與解碼、名稱壓縮、從根伺服器開始的遞迴解析、快取，全部自己實作，沒有用 `net.Resolver`，也沒有任何第三方套件。這個專案的目的是把「輸入網址之後 DNS 到底做了什麼」一步一步攤開來看，所以 README 後半有一整章講 DNS 的運作方式，並附上真實的封包與 `+trace` 輸出。

## 功能

- **訊息編碼/解碼（RFC 1035）**：header 旗標、question、answer / authority / additional、名稱壓縮。
  - 資源紀錄：A、AAAA、CNAME、NS、MX、TXT（多段字串）、SOA、PTR、SRV、CAA、OPT（EDNS0，UDP 大小 1232）。
  - 未知型別依 RFC 3597 顯示成 `\# 長度 十六進位`。
  - 解碼時會擋下壓縮指標迴圈、指向前方的指標、超過 63 bytes 的標籤、超過 255 bytes 的名稱與被截斷的封包。
- **dig 風格的查詢**：`godig example.com MX @1.1.1.1`，輸出有 HEADER、各 SECTION、Query time、SERVER、MSG SIZE。
  - `+short`、`+json`、`+tcp`、`+norec`、`+timeout=`、`+retry=`、`-x`（IPv4 與 IPv6 nibble 格式）、`-p`、`+noedns`。
  - 沒指定 `@server` 時讀 `/etc/resolv.conf`，讀不到就用 1.1.1.1。
- **`godig +trace`**：從內建的 13 個根伺服器（IPv4 與 IPv6 位址）開始自己迭代查詢，逐層印出問了誰、拿到哪些 NS、有沒有 glue。
  沒有 glue 時會先去解析 NS 的名稱；會追 CNAME；有迴圈偵測與最大深度限制。
- **`godig serve`**：小型遞迴解析伺服器（UDP + TCP）。
  - TTL 快取，負面快取依 SOA 的 minimum（RFC 2308）。
  - 並發合併：同一個問題同時來很多請求，只向上游查一次。
  - 每個請求一行記錄。
- **截斷處理**：UDP 回應帶 TC 位元時自動改用 TCP 重查；TCP 使用 2 bytes 長度前綴。
- **防偽造的基本措施**：查詢 ID 用 `crypto/rand`；檢查回應的 ID 與 question 是否和查詢相符；實作 0x20 大小寫隨機化（`+trace` 與 `serve` 預設開啟）。

## 安裝

需要 Go 1.22 或更新版本。

```sh
go install github.com/useless-husband/godig@latest
```

或是到 GitHub Releases 下載預先編譯好的執行檔（darwin-arm64、darwin-amd64、linux-amd64、windows-amd64），放到 `PATH` 裡即可。自己編譯所有平台：

```sh
make release      # 輸出到 dist/
```

## 使用範例

以下輸出都是在有網路的環境實際執行得到的（`WHEN`、查詢 ID 與 TTL 每次都會不同）。

### 一般查詢

```console
$ godig example.com A @1.1.1.1
; <<>> godig <<>> example.com. A
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35822
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232

;; QUESTION SECTION:
;example.com.		IN	A

;; ANSWER SECTION:
example.com.		158	IN	A	104.20.23.154
example.com.		158	IN	A	172.66.147.243

;; Query time: 47 msec
;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)
;; WHEN: Tue Sep 29 06:08:31 CST 2026
;; MSG SIZE  rcvd: 72
```

型別和名稱的順序可以對調（`godig mx gmail.com` 也可以）。

### 只看結果、反查、TXT / CAA / SOA / 未知型別

```console
$ godig +short mx gmail.com @1.1.1.1
5 gmail-smtp-in.l.google.com.
10 alt1.gmail-smtp-in.l.google.com.
40 alt4.gmail-smtp-in.l.google.com.
20 alt2.gmail-smtp-in.l.google.com.
30 alt3.gmail-smtp-in.l.google.com.

$ godig -x 8.8.8.8 +short @1.1.1.1
dns.google.

$ godig -x 2606:4700:4700::1111 +short @1.1.1.1
one.one.one.one.

$ godig +short caa google.com @1.1.1.1
0 issue "pki.goog"

$ godig +short soa example.com @1.1.1.1
elliott.ns.cloudflare.com. dns.cloudflare.com. 2415949263 10000 2400 604800 1800

$ godig +short type65 cloudflare.com @1.1.1.1      # HTTPS 紀錄：godig 不認得，用 RFC 3597 格式顯示
\# 61 0001000001000602683302683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5
```

### JSON 輸出

```console
$ godig +json example.com A @1.1.1.1
{
  "id": 57265,
  "opcode": "QUERY",
  "status": "NOERROR",
  "flags": ["qr", "rd", "ra"],
  "question": [{ "name": "example.com.", "type": "A", "class": "IN" }],
  "answer": [
    { "name": "example.com.", "type": "A", "class": "IN", "ttl": 60, "data": "172.66.147.243" },
    { "name": "example.com.", "type": "A", "class": "IN", "ttl": 60, "data": "104.20.23.154" }
  ],
  "edns": { "version": 0, "udp_size": 1232, "do": false },
  "server": "1.1.1.1:53",
  "protocol": "udp",
  "query_time_ms": 36,
  "msg_size": 72
}
```

（實際輸出是一般縮排的 JSON，這裡為了版面把短陣列排在同一行。）

### +trace

```console
$ godig +trace example.com
; <<>> godig <<>> +trace example.com. A
;; starting from the built-in root hints (13 servers, IPv4), 0x20 case randomization on

;; [1] ask a.root-servers.net. (198.41.0.4#53), zone ".": example.com. A
;;     referral to com. (13 nameservers)
com.			172800	IN	NS	l.gtld-servers.net.
com.			172800	IN	NS	j.gtld-servers.net.
...（其餘 11 行 NS 省略）
;;     glue: l.gtld-servers.net. = 192.41.162.30, 2001:500:d937::30
;;     glue: j.gtld-servers.net. = 192.48.79.30, 2001:502:7094::30
...（其餘 11 行 glue 省略）
;;     received 836 bytes in 62 ms (UDP)
;; [2] ask l.gtld-servers.net. (192.41.162.30#53), zone "com.": example.com. A
;;     referral to example.com. (2 nameservers)
example.com.		172800	IN	NS	hera.ns.cloudflare.com.
example.com.		172800	IN	NS	elliott.ns.cloudflare.com.
;;     glue: hera.ns.cloudflare.com. = 108.162.192.162, 172.64.32.162, 173.245.58.162, 2606:4700:50::adf5:3aa2, ...
;;     glue: elliott.ns.cloudflare.com. = 108.162.195.228, 162.159.44.228, 172.64.35.228, 2606:4700:58::a29f:2ce4, ...
;;     received 359 bytes in 162 ms (UDP)
;; [3] ask hera.ns.cloudflare.com. (108.162.192.162#53), zone "example.com.": example.com. A
example.com.		300	IN	A	104.20.23.154
example.com.		300	IN	A	172.66.147.243
;;     received 72 bytes in 21 ms (UDP)

;; done: NOERROR, 2 answer records, 3 queries sent
```

三步就走完：根伺服器不知道 `example.com` 在哪裡，只告訴你 `com.` 歸誰管；`com.` 的伺服器再告訴你 `example.com.` 的權威伺服器；最後那台直接給答案。沒有 glue 的 NS 會顯示 `has none`，然後縮排一層去解析那個 NS 的位址，可以在 `testdata/golden/trace_noglue.golden` 看到完整的例子。

### serve：自己的遞迴解析伺服器

```console
$ godig serve --port 18183
godig: serving on 127.0.0.1:18183 (udp+tcp); press Ctrl-C to stop
```

另一個終端機用 `dig` 查：

```console
$ dig @127.0.0.1 -p 18183 example.com A +short
104.20.23.154
172.66.147.243

$ dig @127.0.0.1 -p 18183 +tcp example.com MX +short      # 走 TCP
0 .

$ dig @127.0.0.1 -p 18183 example.com A +noall +answer    # 再問一次：由快取回答，TTL 會倒數
```

問一個不存在的名稱（`nonexistent-zzzz.example.com`）會得到 `status: NXDOMAIN`，同樣會被負面快取。

伺服器端每個請求一行記錄，`source` 表示答案從哪裡來（`upstream`、`cache` 或 `coalesced`）；按 Ctrl-C 結束時會印出統計：

```text
2026/09/29 06:09:17 client=127.0.0.1:57232 proto=udp q="example.com. A" rcode=NOERROR answers=2 source=upstream tc=false ms=333
2026/09/29 06:09:17 client=127.0.0.1:62255 proto=udp q="example.com. A" rcode=NOERROR answers=2 source=cache tc=false ms=0
2026/09/29 06:09:17 client=127.0.0.1:54063 proto=udp q="nonexistent-zzzz.example.com. A" rcode=NXDOMAIN answers=0 source=upstream tc=false ms=22
2026/09/29 06:09:17 client=127.0.0.1:51801 proto=tcp q="example.com. MX" rcode=NOERROR answers=1 source=upstream tc=false ms=55
godig: stopped. queries=7 cache_hits=2 cache_misses=5 upstream=5 coalesced=0
```

`godig` 自己也可以當這個伺服器的客戶端：`godig -p 18183 @127.0.0.1 example.com`。預設只監聽 `127.0.0.1`，請不要把它綁在公開位址上當成開放式解析器（沒有限速也沒有存取控制）。

### 所有選項

```text
godig [@server] name [type] [options]
  -p port          伺服器埠（預設 53）
  -t type          記錄型別
  -x address       反查（PTR）
  +short  +json  +tcp  +norec  +noedns
  +timeout=N       每次嘗試等待幾秒（預設 3）
  +retry=N         第一次之外再重試幾次（預設 2）
  +trace           從根伺服器開始迭代
  +ipv6            +trace 時允許使用 IPv6 連線（預設只用 IPv4）
  +0x20 / +no0x20  強制開/關 0x20（+trace、serve 預設開，一般查詢預設關）
godig serve [--port N] [--addr A] [--ipv6] [--quiet] [--no-0x20] [--cache-size N] [--timeout D]
```

## 專案結構

```text
.
├── main.go                    進入點，只負責把參數交給 internal/cli
├── internal/
│   ├── dnsmsg/                訊息編碼/解碼、名稱壓縮、各種 RR、fuzz 測試
│   │   └── testdata/fuzz/     FuzzUnpack 的 seed corpus（含各種惡意封包）
│   ├── resolver/              UDP/TCP 用戶端（ID/question 檢查、0x20、TC→TCP）
│   │                          與迭代解析器（roots.go 是根提示、iterate.go 是遞迴邏輯）
│   ├── server/                TTL 快取（含負面快取）、並發合併、UDP+TCP 伺服器
│   ├── cli/                   參數解析、dig 風格輸出、+trace 輸出、serve 子命令
│   └── fakedns/               測試用的假 DNS 伺服器與假時鐘（只在測試中使用）
├── testdata/golden/           CLI 輸出的 golden file
├── Makefile                   build / test / race / fuzz / release
└── .github/workflows/ci.yml   ubuntu + macOS，go vet 與 go test -race
```

## 如何跑測試

```sh
go vet ./...
go test ./...                    # 全部測試，不需要網路
go test -race -count=1 ./...     # CI 跑的就是這個
make fuzz                        # 真正的 fuzz（預設 30 秒）；CI 只跑 seed corpus
go test ./internal/cli -update   # 改了輸出格式後重新產生 golden file
```

測試的設計原則：

- **不碰網路。** `internal/fakedns` 在 `127.0.0.1` 的隨機埠同時起 UDP 與 TCP 的假伺服器，測試裡模擬 root → TLD → 權威伺服器的委派鏈、CNAME 鏈、沒有 glue 的 NS、NS 名稱互相依賴形成的迴圈、UDP 截斷、逾時、SERVFAIL、假冒的封包等情況。假伺服器用的是文件保留位址（192.0.2.0/24），解析器的 `Addr` 掛勾把它們對應到本機埠。
- **不依賴真實時間。** 快取與委派快取的 TTL 使用假時鐘；RTT 也用假時鐘量，所以 golden file 裡的 `Query time` 永遠是固定的數字。
- **決定性。** 查詢 ID 與 0x20 的隨機位元可以從測試注入。
- 涵蓋範圍：每種 RR 的 round-trip、名稱壓縮（含惡意封包：指標迴圈、指向前方、標籤超長、名稱超過 255、任何長度的截斷）、fuzz seed corpus、遞迴邏輯、快取 TTL 與負面快取、`-race` 下的並發合併、CLI 輸出的 golden file。

---

# DNS 是怎麼運作的

這一章順著 godig 的實作，從封包的每個 byte 講到完整的解析過程。

## 1. 大局

瀏覽器要連 `www.example.com`，需要 IP 位址。它把問題丟給**遞迴解析器**（recursive resolver，通常是路由器、ISP 或 1.1.1.1 這類服務）。解析器如果沒有答案，就從**根伺服器**開始，一層一層問下去，直到問到**權威伺服器**（authoritative server）拿到答案為止；沒有 `+trace` 的時候這一切都發生在你看不到的地方。

```text
瀏覽器 ──▶ 遞迴解析器 ──▶ 根伺服器       「www.example.com？」  「不知道，問 com. 的伺服器」
                    ├──▶ com. 伺服器     「www.example.com？」  「不知道，問 example.com. 的伺服器」
                    └──▶ example.com. 伺服器  「www.example.com？」  「93.184.…」
```

godig 兩邊都做：`godig example.com @1.1.1.1` 扮演**存根解析器**（stub），把問題丟給別人；`godig +trace` 和 `godig serve` 扮演遞迴解析器，自己去問。

## 2. 訊息格式，逐位元組

DNS 訊息不管是查詢還是回應，格式都一樣：一個 12 bytes 的 header，後面接四個區段（question、answer、authority、additional）。

```text
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |   byte 0-1
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |   byte 2-3
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |   byte 4-5   question 的數量
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |   byte 6-7   answer 的數量
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                   |   byte 8-9   authority 的數量
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |   byte 10-11 additional 的數量
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

所有多 byte 的數字都是大端序（network byte order）。旗標的意思：

| 位元 | 意思 |
| --- | --- |
| QR | 0 是查詢，1 是回應 |
| Opcode | 0 = 標準查詢 |
| AA | 回答的伺服器對這個名稱是權威 |
| TC | 訊息太大被截斷了（見第 8 節） |
| RD | 要求對方幫忙遞迴（Recursion Desired）。stub 送 1；解析器問權威伺服器時送 0 |
| RA | 對方願意遞迴（Recursion Available） |
| AD / CD | DNSSEC 用的位元，godig 只是原樣顯示 |
| RCODE | 0 NOERROR、2 SERVFAIL、3 NXDOMAIN（名稱不存在）、5 REFUSED … |

### 真實範例：查詢

`godig example.com A` 送出的查詢（不含 EDNS，ID 用 0x1234 當例子）共 29 bytes：

```text
12 34               ID = 0x1234
01 00               旗標 = 0000 0001 0000 0000 → 只有 RD 為 1
00 01               QDCOUNT = 1
00 00 00 00 00 00   ANCOUNT = NSCOUNT = ARCOUNT = 0
07 65 78 61 6d 70 6c 65    07 "example"          ← 名稱是「長度 + 內容」的標籤序列
03 63 6f 6d                03 "com"
00                         00 結尾（根標籤）
00 01               QTYPE  = 1 (A)
00 01               QCLASS = 1 (IN)
```

實際的 godig 查詢還會附上一筆 OPT 紀錄（EDNS0，見第 10 節），所以會多 11 bytes。

### 真實範例：回應

我用 Python 的 socket 對 1.1.1.1 送出上面那個查詢，收到 61 bytes 的回應：

```text
offset  bytes                                    意思
------  ---------------------------------------  ------------------------------------------
 0      12 34                                    ID，與查詢相同
 2      81 80                                    1000 0001 1000 0000 → QR=1, RD=1, RA=1, RCODE=0
 4      00 01  00 02  00 00  00 00               1 個 question、2 個 answer
12      07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   question：example.com.   (offset 12 開始)
        00 01  00 01                             TYPE=A, CLASS=IN
29      c0 0c                                    answer 1 的名稱：指標，指向 offset 12
        00 01  00 01                             TYPE=A, CLASS=IN
        00 00 00 2c                              TTL = 44 秒
        00 04                                    RDLENGTH = 4
        ac 42 93 f3                              RDATA = 172.66.147.243
45      c0 0c                                    answer 2 的名稱：同一個指標
        00 01  00 01  00 00 00 2c  00 04
        68 14 17 9a                              RDATA = 104.20.23.154
```

每一筆資源紀錄（RR）的格式：`名稱 | TYPE(2) | CLASS(2) | TTL(4) | RDLENGTH(2) | RDATA`。RDATA 的內容因型別而異：A 是 4 bytes、AAAA 是 16 bytes；MX 是 2 bytes 優先度加一個名稱；TXT 是一串「1 byte 長度 + 內容」的字串（所以單一字串最長 255 bytes，長的 TXT 會被切成多段）；SOA 是兩個名稱加五個 32 位元整數；SRV 是三個 16 位元整數加一個名稱；CAA 是 flags、tag 長度、tag、value。不認得的型別，godig 會把 RDATA 原封不動保留，用 RFC 3597 的 `\# 長度 十六進位` 顯示。

## 3. 名稱與壓縮指標

名稱由標籤（label）組成，每個標籤最長 63 bytes，整個名稱在線路上最長 255 bytes（含長度 byte 和結尾的 0）。名稱常常重複出現（像上面兩筆 answer 的名稱都是 `example.com.`），所以協定允許壓縮：

```text
標籤長度 byte 的最高兩個位元：
  00xxxxxx  普通標籤，後面跟 xxxxxx 個 bytes
  11xxxxxx  指標：這個 byte 加下一個 byte 共 14 位元，是「訊息開頭算起的偏移量」，名稱從那裡接著讀
  01 / 10   保留，godig 直接拒絕
```

上面的 `c0 0c` 就是 `11 000000 00001100`：指向 offset 12，也就是 question 裡 `example.com.` 開始的位置。

**編碼**時，godig 記住每個已寫出的名稱後綴（不分大小寫）在哪個 offset，之後遇到相同後綴就寫指標。例如 CNAME 的目標 `web.example.com.` 只需要寫 `03 "web"` 再接一個指向 `example.com.` 的指標。SRV 的目標名稱依 RFC 2782 不壓縮。

**解碼**才是危險的地方，因為指標是攻擊者可以控制的。godig 的規則（`internal/dnsmsg/name.go` 的 `readName`）：

- 指標必須指向**它自己之前**的位置。指向前方或指向自己，直接回 `ErrBadPointer`。
- 跳轉次數有上限（16 次）。即使每個指標都指向前面，攻擊者仍可以讓「標籤 → 指標 → 回到同一個標籤」形成迴圈，上限會讓它以 `ErrPointerLoop` 結束。
- 展開後的名稱超過 255 bytes 就停（`ErrNameTooLong`），單一標籤超過 63 bytes 或使用保留的標籤類型也拒絕。
- 每個讀取動作都先檢查是否超出封包（`ErrShort`）；RDLENGTH 宣告的長度必須和實際解析吃掉的長度完全一致。
- 一開始就用 header 裡的數量檢查「這個封包至少要多長」，避免宣稱有 65535 筆紀錄的小封包讓程式先配置大量記憶體。

這些行為由單元測試與 fuzz 測試守住：`FuzzUnpack` 要求「能解碼的東西重新編碼再解碼要得到相同結果，不能 panic」。

## 4. 從根伺服器開始的遞迴過程

遞迴解析器手上只有一份「根提示」（root hints）：13 個根伺服器（a.root-servers.net 到 m.root-servers.net）的位址，內建在 `internal/resolver/roots.go`。之後的每一步都是同一個動作：

1. 問目前這一層的某台伺服器：「`www.example.com` 的 A 紀錄是什麼？」（RD = 0，因為我們不要求對方幫忙）。
2. 看回應：
   - **answer 區段有資料** → 完成。
   - **authority 區段有 NS 紀錄，指向更深的區域**（referral，委派）→ 換成那個區域的伺服器，回到步驟 1。
   - **NXDOMAIN** → 名稱不存在。
   - **NOERROR 但什麼都沒有，帶著 SOA** → 名稱存在，但沒有這個型別（NODATA）。

前面「使用範例」裡 `godig +trace example.com` 的輸出就是這三步。godig 對委派有幾條防呆規則（`iterate.go`）：

- **必須往下走。** 新的區域必須比目前的區域「更深」，而且查詢的名稱要在它底下。往上或平行的委派一律忽略，所以委派本身不可能繞圈子。
- **伺服器失敗就換下一台。** 逾時、SERVFAIL、REFUSED，以及「lame」的回應（NOERROR、不是權威、沒有答案也沒有委派）都會讓 godig 換下一個 NS。
- **最大限制。** 委派跳數（預設 16）、CNAME 鏈長度（8）、巢狀查詢 NS 位址的深度（6）、單一問題的上游查詢總數（64）。

## 5. Glue record

問題來了：`example.com.` 的 NS 是 `hera.ns.cloudflare.com.`，要問它就得先知道它的 IP，而要知道它的 IP 又得查 DNS。如果 NS 的名稱本身就在被委派的區域裡（例如 `example.com.` 的 NS 叫 `ns1.example.com.`），就會變成死結：要找 `ns1.example.com` 得先問 `example.com.` 的伺服器，而那正是 `ns1.example.com` 自己。

解法是 **glue record**：父區域的伺服器在回應的 additional 區段附上這些 NS 的位址。`+trace` 輸出裡的 `glue:` 行就是這個。

```text
;; [1] ask a.root-servers.net. ... zone ".": example.com. A
;;     referral to com. (13 nameservers)
com.   172800 IN NS l.gtld-servers.net.        ← authority 區段
;;     glue: l.gtld-servers.net. = 192.41.162.30, 2001:500:d937::30    ← additional 區段
```

有兩件事要小心：

- **只相信 in-bailiwick 的 glue。** 一台伺服器如果在 additional 區段塞了「順便附贈」的、不在它管轄範圍的位址（例如 `com.` 的伺服器附上 `ns.victim.net.` 的位址），這是快取投毒的經典手法。godig 只接受名稱在**回答者所屬區域底下**、而且確實是這次委派的 NS 之一的 glue（`buildDelegation`，有測試 `TestGlueOutsideBailiwickIgnored`）。
- **沒有 glue 怎麼辦。** 當 NS 在別的區域（例如 `nogl.test.` 的 NS 是 `ns.provider.test.`），父區域不會附 glue。godig 先嘗試已有位址的 NS；沒有的話，才另起一個完整的解析去查那個 NS 的 A 紀錄，再回來繼續。這個巢狀查詢有深度上限，並且記錄「正在解析哪些 NS 名稱」，如果 A 的位址要靠 B、B 又要靠 A，就會被偵測出來並跳過，而不是無限遞迴。`+trace` 會把巢狀查詢縮排一層印出來。

## 6. CNAME 追蹤

CNAME 是別名：`www.example.com CNAME example.com.` 表示「這個名稱的所有資料都去看那個名稱」。解析器遇到時要改問目標名稱：

- 目標在同一個區域時，權威伺服器通常會直接把 CNAME 和目標的 A 一起放在 answer 區段。
- 目標在別的區域時，答案只有 CNAME，解析器得**重新從頭**（或從快取的委派）解析目標，再把兩段答案接起來。

godig 的處理（`followChain` 與 `Resolver.resolve`）：

- 沿著 answer 區段從查詢名稱走一遍，只保留這條鏈上的紀錄。伺服器多塞的無關紀錄（例如順便給的 `bank.example.` 的 A）會被丟掉。
- 鏈沒走完（最後是個沒有資料的 CNAME）就對目標重新解析；用集合記錄看過的名稱，遇到 `a → b → a` 這種迴圈就報錯；CNAME 總數超過 8 也報錯。
- 如果查的型別本身就是 CNAME，則不追。

## 7. TTL 與快取

每筆 RR 的 TTL 是「這筆資料最多可以被快取多少秒」。`godig serve` 的快取（`internal/server/cache.go`）：

- 一個答案集合的 TTL 取裡面**最小**的 TTL（CNAME 鏈中任何一環過期，整個答案就不能用）。TTL 為 0 不快取；上限預設 1 天。
- 從快取回答時，TTL 會扣掉已經在快取裡待的時間，所以你連續問會看到 TTL 一路倒數。
- **負面快取（RFC 2308）：** NXDOMAIN 和 NODATA 也要快取，否則每次查一個不存在的名稱都會打到權威伺服器。快取時間是 `min(SOA 紀錄的 TTL, SOA 的 MINIMUM 欄位)`，上限預設 1 小時；沒有附 SOA 的負面回應就不快取。快取裡的 SOA 也會跟著倒數。
- SERVFAIL、逾時這類錯誤不快取。
- 除了答案快取，解析器還有一份**委派快取**（`ZoneCache`）：知道 `example.com.` 的權威伺服器是誰之後，下次問 `mail.example.com` 就不用再問根和 `com.` 了。快取時間是 NS 紀錄的 TTL，上限一天；`+trace` 不使用它，永遠從根開始。

測試裡的時間全部來自假時鐘，例如「TTL 60 的紀錄在 59 秒時仍有效、60 秒時過期」是精確驗證的。

### 並發合併

如果 50 個客戶端在同一瞬間問同一個沒快取的名稱，天真的做法是向上游查 50 次。godig 的 `group`（其實就是 singleflight）以「名稱 + 型別」為 key，第一個請求負責查，其餘的等它的結果。上游查詢用獨立的 context，所以領頭的客戶端斷線不會讓其他等待者一起失敗。測試 `TestHandleCoalescesConcurrentIdenticalQueries` 用 25 個 goroutine 驗證上游只被呼叫一次。

## 8. 截斷與 TCP 退回

DNS 原本只用 UDP，而 UDP 訊息最多 512 bytes（沒有 EDNS 時）。回應放不下時，伺服器要盡量放、並把 **TC（truncated）位元**設為 1，意思是「你拿到的不完整，請改用 TCP 重問」。

TCP 上的 DNS 訊息前面多 2 bytes 的長度（大端序），因為 TCP 是串流，沒有訊息邊界：

```text
00 3d  12 34 81 80 00 01 ...        長度 0x003d = 61，後面是完整的 61 bytes 訊息
```

godig 用戶端的流程（`internal/resolver/client.go`）：先用 UDP 送出，收到回應如果 `Truncated` 為 1，就在同一台伺服器開 TCP 連線把同樣的問題再問一次（`Response.FellBackToTCP` 會記錄這件事，dig 風格的輸出也會印 `;; Truncated, retrying in TCP mode.`）。收到被截斷的回應時，封包可能在某筆 RR 中間就斷了，所以這種回應只需要 header 和 question 完整（`UnpackTruncated`）。

有了 EDNS0（第 10 節）之後 UDP 可以更大，但 godig 只宣告 1232 bytes：這是 2020 年 DNS Flag Day 建議的值，讓整個封包放得進常見的 1280 bytes IPv6 最小 MTU，不用靠 IP 分片，因為分片正是偽造回應的一種途徑。`godig serve` 對 UDP 客戶端也是取 `min(客戶端宣告的大小, 1232)` 作為上限，超過就送出只有 question 且 TC=1 的回應。

## 9. 防偽造：ID、question 與 0x20

DNS 傳統上用 UDP，而 UDP 沒有連線，任何人都可以偽造來源位址送封包。**DNS 快取投毒**攻擊就是：攻擊者猜到解析器送出的查詢，搶在真正的伺服器之前送出一個偽造的回應，解析器把假答案收進快取，之後所有使用者問到這個名稱都被導向攻擊者。2008 年 Kaminsky 攻擊把這件事變得非常實際：攻擊者不必等，只要大量查詢同一個網域下不存在的名稱，就有無數次機會。

回應要被接受，必須猜對的東西越多，攻擊越難：

1. **16 位元的查詢 ID。** godig 使用 `crypto/rand`，不是 `math/rand`，因為可預測的 ID 等於沒有 ID。
2. **question 必須完全相同。** 回應必須只有一個 question，名稱、型別、類別都和查詢一致。ID 相同但問題不同的封包會被忽略（`matches`）。
3. **來源埠。** godig 對每次查詢都用 `net.Dial` 建立新的、由作業系統隨機分配埠的已連線 UDP socket，核心只會把來自那台伺服器位址與埠的封包交給我們。ID 加埠大約是 32 位元的猜測空間。
4. **不合格的封包不會讓查詢失敗，只是被忽略。** 客戶端會繼續等真正的回應直到逾時，攻擊者無法用亂送封包來讓查詢提前失敗（否則偽造封包也成了阻斷服務的工具）。
5. **0x20 大小寫隨機化。** DNS 名稱不分大小寫，但伺服器回應時必須把 question 的名稱原樣照抄。所以 godig 送出 `eXaMpLe.CoM.` 這種隨機大小寫的名稱（每個字母用一個隨機位元決定），回應的 question 不是同樣的大小寫就丟掉。一個 12 個字母的名稱多出 12 位元的熵。這個方法來自 Dagon 等人 2008 年的 "0x20-bit encoding" 論文，Unbound 之類的解析器也有實作。
   - 少數伺服器會把名稱轉成小寫再回。遇到這種伺服器，godig 會因為所有回應都不合格而逾時，接著自動用不隨機大小寫的名稱再試一次（Unbound 稱為 fallback），所以還是查得到，只是慢一點、防護少一層。
   - 為了讓輸出好看，通過檢查之後 godig 會把回應裡的名稱還原成使用者輸入的大小寫（`restoreCase`）；否則壓縮指標會讓 `hera.ns.cloudflare.Com.` 這種大小寫參差的名稱到處出現。
6. **bailiwick 檢查。** 前面提過：glue 只收管轄範圍內的；answer 區段只保留 CNAME 鏈上的紀錄；委派只往下走。

這些措施都不能取代 DNSSEC（用簽章驗證資料本身），godig **沒有**實作 DNSSEC 驗證。

## 10. EDNS0

原本的 DNS 格式沒有地方放新功能，也限制 UDP 512 bytes。RFC 6891 的 EDNS0 用一筆假的資源紀錄 **OPT** 放在 additional 區段來擴充：

```text
00                  名稱：根（一個 0 byte）
00 29               TYPE = 41 (OPT)
04 d0               CLASS 欄位被借來放「我能收多大的 UDP 封包」：0x04d0 = 1232
00 00 00 00         TTL 欄位被借來放：擴充 RCODE、版本、旗標（DO 位元表示要 DNSSEC 資料）
00 00               RDLENGTH，後面是 {選項代碼, 長度, 資料} 的列表（這裡沒有選項）
```

godig 預設會附上 OPT（`+noedns` 可以關掉），伺服器端也會在客戶端有送 OPT 時回一個。dig 風格的輸出把它印在 `OPT PSEUDOSECTION`，而不是當成普通的 additional 紀錄。

---

## 已知限制

- 沒有 DNSSEC 驗證（AD / CD 位元只是原樣顯示）；沒有 DoT / DoH / DoQ。
- `godig serve` 是學習用的：沒有限速、沒有存取控制、沒有 ECS、沒有 stale 快取、沒有 `/etc/hosts` 與搜尋網域。預設只綁在 `127.0.0.1`。
- 迭代解析預設只使用 IPv4 連線（IPv6 位址仍會被顯示出來，加上 `+ipv6` 或 `serve --ipv6` 才會真的使用），因為許多網路沒有可用的 IPv6。
- 查詢名稱不做 IDN / punycode 轉換，請自己輸入 `xn--` 形式。
- 只支援 `IN` 類別；`serve` 會對 CHAOS 類別與 AXFR/IXFR 回 REFUSED。
- 沒有指定 `@server` 時只讀 `/etc/resolv.conf` 的第一個 `nameserver`；macOS 的系統解析設定不在這個檔案裡時會退回 1.1.1.1。Windows 沒有這個檔案，同樣會退回 1.1.1.1。

## 授權

[MIT](LICENSE) © 2026 useless-husband
