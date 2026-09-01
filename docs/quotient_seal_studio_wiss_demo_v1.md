# QuotientSeal Studio WISS Demo v1

## デモの目的

WISS Demo Directorは、QuotientSealの研究主張を90秒で説明しながら、聴衆が同じ画面を自由探索できるsoftware-onlyのデモ導線である。新しいsecurity判定を追加せず、既存のcapsule、attack、trace、repair、revalidation artifactを再利用する。

## 90秒choreography

| 時間 | Act | 説明 |
|---:|---|---|
| 0–12秒 | Capsule | 許可されたsurfaceとTCB-only境界を示す |
| 12–32秒 | Attack | action-equivalentな実行を区別する反例を再生する |
| 32–50秒 | Microscope | first divergenceとobserver surfaceを追う |
| 50–72秒 | Repair | QuotientPad候補をsecurity/performanceへ再投入する |
| 72–90秒 | Boundary | digest-linked summaryと未検証境界をexportする |

launcherを開いて「攻撃へ直行」を押す2操作で最初の攻撃へ到達できる。guided modeは時間に応じて自動でActを進めるが、前後キー、timeline、左右矢印キーで任意に移動できる。自由探索へ切り替えると自動進行とfocus表示を停止する。

## Demo stories

攻撃は固定seedの次の3種を切り替える。

- Extra host call
- Private-dependent trap
- Resource-only leak

修復比較は次の4つを保持する。

- security VALID / performance PASS
- security INVALID / performance PASS
- security VALID / performance FAIL
- security INCONCLUSIVE / performance INCONCLUSIVE

## Shareable export

exportは64 KiB未満の決定的JSONであり、次だけをallowlistする。

- choreography
- capsuleのtri-state verdict、理由、digest
- attackのscenario、seed、verdict、observer、mutation、artifact digest
- repairのsecurity/performance verdictとartifact digest
- evidence origin、hardware status、claim boundary

raw biosignal、PPG/IBI sample、secret key、subject ID、stable identifier、自由入力はexportしない。export自体もSHA-256で識別する。

## Accessibility

- 操作はbutton要素とdialog landmarkで提供する。
- `Escape`でDirectorを閉じ、左右矢印でActを移動できる。
- mobileではsafe-areaを考慮した全幅panelになる。
- `prefers-reduced-motion`ではscrollとfocus animationを停止する。
- verdictは色だけでなく、語、記号、形状で区別する。

## Claim boundary

- `evidence_origin = SOFTWARE_FIXTURE`
- `hardware_status = NOT_VERIFIED`
- Polar Verity Senseとの実機接続、実時間性能、実biosignalはこのデモでは検証しない。
- performance PASSはsecurity verdictではない。
- candidate new primitiveの説明用であり、world-firstを断定しない。

