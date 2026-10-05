# K7 publication artifacts v1

K7-16dは検証済みrun logだけから、canonical JSON summary、CSV table、SVG figureを決定的に再生成する。
raw private dataやhost pathは入力にせず、run logと全task resultのdigestをfull recomputationしてから生成する。

```bash
python -m noticer_core.replication.k7_publication \
  --run-log artifacts/k7_replication/run-log.json
```

固定taxonomyは`PASS`、`FAILED`、`TIMEOUT`、`UNAVAILABLE`、`OUTPUT_LIMIT`、`BLOCKED`である。
件数0のstatusもsummaryとfigureへ残し、欠測、timeout、inconclusive相当の状態を図表から消さない。
SVGは外部fontや時刻metadataを含まず、CSVはLF改行で生成する。manifestは3生成物のbyte数とSHA-256、
source run digestを束縛する。出力は`artifacts/k7_replication/publication/`配下へ生成しGitへcommitしない。

図表生成の成功はsecurity verdict、統計的有意性、独立再現、hardware検証を意味しない。
