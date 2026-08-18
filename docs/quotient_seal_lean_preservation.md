# RAQTR Preservation in Lean 4

## 1. 目的

K8-09は、独立checkerが再計算したsource-target relationと閉じたfinite context
productから、任意の有限prefixに対するRobust Action-Quotient Trace Refinement
（RAQTR）とutility preservationをLean 4で導く。

この証明はK7の`AQRS.Model`、`BoundedAQNI`、`UtilitySafeThrough`を直接再利用する。
Rust側の型やcertificateをLean内へ複製しない。compiler名、engine名、manifestの自己申告は
定理の仮定に含めない。

## 2. Formal objects

`Aqrs.QuotientSeal.Model`は次を明示する。

- restricted target stateとadversarial context state
- sourceと同じpublic input、action、release、observer domain
- observer profile別のtarget projection
- source-target abstraction relation
- one-step、semantic、observation、actionの保存条件
- target-only trap、forbidden import、resource bound
- resource trace equality
- finite coupled-product entries、明示的product bound、closure、bad-state不在

observer projectionはAPI、control、instruction、memory、resourceのいずれも表現できる抽象型とし、
特定engineのnative instruction traceとは同一視しない。

## 3. Planned theorem chain

1. validated relationがsource/target one-step後にも保存される。
2. relationから各slotのtarget observationとsource projectionが一致する。
3. 同じpublic tapeと等しいobservationからcontext couplingが保存される。
4. finite product closureから任意の有限slotのmembershipを帰納的に得る。
5. K7 bounded AQNIとprojection保存からtarget間trace equalityを得る。
6. action listの保存とK7 utility仮定からtarget utility preservationを得る。
7. trap、forbidden import、resource bound、resource-only差分をbad stateへ接続する。

最終定理はobserver profile、finite domain、product bound、finite horizon、source AQNI、source
utility、relation witnessを引数へ明示する。

## 4. Mechanized theorem

`AQRS.QuotientSeal.finiteProductPreservesRAQTR`は、任意に与えた有限`horizon`について
次を同時に返す。

- selected observer profileでのtarget trace equality
- adversarial context stateのcoupling
- target resource trace equality
- target-only trap、forbidden import、resource boundの不在
- source releaseとtarget releaseのaction list一致
- K7 `UtilitySafeThrough` witnessの保持

finite productのentry数と`productBound`は結論へ残る。closureは全slotのpublic inputに対して
要求されるため、特定の学習済みprefixだけを列挙して成功扱いすることはできない。

## 5. Negative models

- `suppress-all`: sourceで必要なactionをtargetが消すためaction refinementを満たさない。
- `resource-only leak`: release payloadとactionが同じでもprivate run間のresource traceが異なり、
  `resourceMismatch` bad stateを持つ。

negative modelは「観測を消せば安全」という退化解と、機能出力だけを比較する不十分なcheckerを
排除するために使う。

## 6. Verification boundary

- Lean toolchainは`formal/aqrs/lean-toolchain`へpinする。
- kernel buildに加えてGitHub Actionsのindependent `leanchecker`で再検証する。
- theoremの公理面は`propext`だけを許可し、`Classical.choice`、`Quot.sound`、
  `sorryAx`をCIで拒否する。
- proof escape hatchをsource guardで拒否する。
- nanodaはLean 4.30 export incompatibilityを解消するまで`NOT_VERIFIED`である（#115）。
- RustからLean modelへのlowering correctnessは本Issueの証明対象外である。
- infinite-trace liveness、native JIT、OS、microarchitecture、hardwareは証明対象外である。
- 実hardware状態は`NOT_VERIFIED`である。
- 新規性、優先権、world-firstは断定しない。
