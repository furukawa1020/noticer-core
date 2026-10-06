# K5 hardware preflight seal

実機計測の開始前に、対象Tier、K5 protocol、toolchain、private storage、同意、安全手順、
停止条件、役割分離した承認を同一planへ束縛する。封印はdomain-separated SHA-256を使い、
JSON key順序やWindows/Linuxの改行表現に依存しないcanonical JSONから計算する。

公開planにはsalt付きcommitmentだけを置く。同意本文、氏名、participant/device identifier、
raw biosignal、鍵、nonce本体は含めない。operatorとsafety reviewerのapproval commitmentは
異なる値を要求するが、このsoftware契約だけで人物の独立性を証明したとは扱わない。

preflightは計測実施の証拠ではない。`status = NOT_VERIFIED`、`evidence_origin = NONE`だけを
受理し、CI成功や封印成功によってTier B/C/D/S3を昇格させない。実測時は封印digestをprivate
measurement bundleとpublic hardware artifactの双方へ記録し、後付けのprotocol差替えを拒否する。

```powershell
$env:PYTHONPATH = "src"
python tools/seal_k5_hardware_preflight.py seal --input private/preflight.json --output artifacts/k5-hardware/preflight.json
python tools/seal_k5_hardware_preflight.py verify --input artifacts/k5-hardware/preflight.json --protocol configs/k5/hardware_protocol.yaml
```

生成artifact、private plan、salt、承認原文はGitへcommitしない。
