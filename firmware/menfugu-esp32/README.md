# ESP32 めんふぐadapter

このcrateはESP-IDF GATT callbackとGPIO driverをK4のplatform-neutral runtimeへ接続する薄い
境界である。repositoryのworkspace CIにはESP-IDF toolchainを要求しないため、独立workspaceに
している。

統合時は次を固定する。

1. GATT characteristicは20-byte writeだけをruntimeのon_gatt_writeへ渡す。
2. monotonic public tickと公開execution slotをcallbackへ渡す。
3. timer callbackはon_public_timerを呼ぶ。
4. boot直後とerror時はGPIOをlowへする。
5. verifier key、revocation、replay stateを永続化する。
6. BLE error detailをpeerへ返さない。

実機、ESP-IDF、GPIO、pumpを用いたTier B試験はこのコミットではNOT_VERIFIEDである。
