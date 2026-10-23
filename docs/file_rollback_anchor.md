# File-backed rollback anchor

`FileRollbackAnchorStore`はrollback anchorを176 byteの固定長recordとしてappendし、各append後に`sync_data`する。

- magic、version、reserved bytesを検証する。
- partial record、容量超過、同時writerをfail closedで拒否する。
- file内容の認証とchain検証は`DurableRollbackAnchor::open`が行う。
- lockfileはprocess内の同時writerを排除し、store drop時に除去する。

filesystem自体のrollback耐性は外部のmonotonic storageまたはplatform secure counterとの組合せで強化する。
