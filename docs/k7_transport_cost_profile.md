# K7 Transport Cost Profile

K7-14bはsecurity contract、logical cost、platform profileを3つの独立digestとして保持する。profile変更はmeasurementのidentityだけを変え、security contractやlogical costのidentityを変更しない。

profileは公開source、version、SHA-256、measurement environmentを必須とする。現在のevidence kindは`SOFTWARE_PROXY`だけであり、測定区間は`lower <= estimate <= upper`を満たす有限非負値でなければならない。

software proxyをjoule、Wh、mAhなどのhardware energy単位として報告することは禁止する。実hardware校正は別profileと別evidence tierを定義してから追加する。
