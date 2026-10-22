# Receipt鍵rotationと暗号学的消去

`ReceiptKeyring`はepochごとの鍵materialを`Zeroizing`で所有する。新epochを登録・activateしてから旧epochをretireする。

- active epochはretireできない。
- 未完了transactionが参照するepochはretireできない。
- retire時に鍵materialをmapから除去し、drop時にzeroizeする。
- retired epochは再登録・再activateできず、そのepochのreceiptも検証できない。
- retired epoch集合は鍵materialとは別に永続化し、restart後も再利用禁止を復元する。

呼び出し側はoutboxの`PENDING`と`DELIVERED`が参照する`receipt_epoch`集合をretire ceremonyへ渡す。空集合を渡してよいのは、認証付きcompaction後に未完了参照がないことを確認した場合だけである。
