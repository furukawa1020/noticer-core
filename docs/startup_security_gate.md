# Startup cross-store certification gate

release開始前にcross-store certificateとrollback anchorの両方を検証し、その結果を`StartupAuthorization`へ束縛する。

- certification失敗時はauthorizationを生成しない。
- stale、future、cross-store mixed anchorを拒否する。
- authorizationはcertificate authenticator、anchor generation、anchor authenticatorをHMACで認証する。
- release側はauthorizationを再検証し、phase skipやcomponent substitutionを拒否する。

診断処理とbacklog recoveryは実行できるが、新規releaseは有効なauthorizationが得られるまで開始してはならない。
