# K7 public artifact audit v1

K7-16eは独立再現packageのexact file inventory、environment・run log・publication digest chain、
private-field非混入をboundedに監査する。監査対象はpolicyで許可した6ファイルだけであり、欠落と余剰を拒否する。

```bash
python -m noticer_core.replication.k7_audit \
  --package artifacts/k7_replication/package
```

監査はfile・total byte上限、JSON key denylist、credential pattern、credential-like suffix、Windows/Linuxの
absolute home pathを検査する。environment report、task result、run log、summary、CSV、SVG、publication
manifestは保存値を信頼せず再計算する。findingが1件でもあれば`verdict: FAIL`、`release_blocker: true`、
exit code 2となり、欠測や改変をPASSへ丸めない。

これは限定された構造・pattern監査であり、情報漏えい不存在の証明、security verdict、hardware検証ではない。
生成audit reportは`artifacts/`配下へ置きGitへcommitしない。
