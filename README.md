# Pi-hole Blocklist (Collect and Organize By AllenYen)

家母最近迷上了看中國的網路小説，網站中充斥著各種廣告及病毒<br>
最近閒閒沒事，剛好手邊有一塊沒在用的RaspberryPi 3，於是就在家裡弄了個Pi-hole來擋擋廣告<br>
分享一下我所使用的BlockList給大家參考

## 使用方式

Pi-hole 只要加入這**一個**網址就好：

```
https://github.com/tntrock/Pi-hole-Block-list/releases/download/blocklist/blocklist.txt
```

- Pi-hole v6：Lists → 貼上網址 → Add blocklist，再到 Tools → Update Gravity
- Pi-hole v5：Group Management → Adlists → 貼上網址 → Add，再執行 `pihole -g`

每天台灣時間凌晨 2:23 由 GitHub Actions 自動重新產生。每次建置的報告（各來源狀態、數量、白名單命中）
在 [Releases 頁面](https://github.com/tntrock/Pi-hole-Block-list/releases/tag/blocklist)。

## 自動化做了什麼

1. 下載 [`sources.txt`](sources.txt) 裡的所有清單（hosts、純網域、`||domain^`、CSV 格式都能讀）
2. 正規化（轉小寫、中文網域轉 punycode、剔除 IP / localhost / 格式錯誤）並**去除重複**
3. **剔除過時來源**：超過 365 天沒更新的來源自動略過；已下線的來源會標在報告裡
4. **套用白名單**，避免一般常用服務被誤擋：
   - [`allowlist.txt`](allowlist.txt)：手動維護（台灣政府/學校/銀行、LINE、Google、Apple、Microsoft、串流等）
   - [`allowlist-sources.txt`](allowlist-sources.txt)：社群整理的常見誤擋清單
5. 安全機制：
   - 來源暫時下載失敗 → 沿用最近 7 天內的快取，不會讓清單突然變少
   - 總數比上次少 30% 以上 → 判定異常，不發佈，Pi-hole 繼續用舊的那份

## 常見操作

| 想做的事 | 怎麼做 |
|---|---|
| 新增來源 | 在 `sources.txt` 加一行網址，push 後會自動重建 |
| 某網站被誤擋 | 在 `allowlist.txt` 加 `example.com`（只放行它）或 `*.example.com`（連同子網域） |
| 立刻重建 | Actions → Build blocklist → Run workflow |
| 刻意大幅刪減來源 | Run workflow 時勾選「略過數量驟減安全檢查」 |

## 來源

見 [`sources.txt`](sources.txt)，包含：

- 廣告：AdAway、StevenBlack、AdGuard DNS、EasyList、anudeepND、Disconnect、yoyo、hostsVN
- 追蹤：EasyPrivacy、Prigent、frogeye first-party trackers、KADhosts
- 惡意 / 釣魚 / 詐騙：HaGeZi Threat Intelligence Feeds、Phishing Army、malware-filter (URLhaus / Phishing)、DandelionSprout Anti-Malware、NoTrack
- **台灣在地詐騙網域**：[警政署 165「遭停止解析涉詐網站」開放資料](https://data.gov.tw/dataset/176455)
- BlocklistProject 分類清單（惡意、詐騙、釣魚、賭博、色情、TikTok、追蹤…）

已停用的舊來源與原因保留在 `sources.txt` 檔尾。
