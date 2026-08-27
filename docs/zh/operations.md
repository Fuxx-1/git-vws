# 运行与运维

[中文](operations.md) | [English](../en/operations.md) | [返回中文首页](../../README.md)

本页说明安装、使用 session、发布、清理和恢复。请保留 create 输出的准确 session root；该 session 只应编辑这个目录。

## 安装

可以从源码构建，也可以从 GitHub Releases 下载对应归档。将其中的 git-vws 放入 PATH，然后确认 Git 能发现它：

    git vws --version
    git vws -h

当前版本支持 macOS APFS，以及通过 native COW 检查的 Linux 文件系统。它不安装 FUSE、内核扩展、后台服务或管理员 helper。

## Session 生命周期

    git vws init /path/to/project
    git vws --repo /path/to/project create feature-a --target feature/a
    git vws --repo /path/to/project list
    git vws --repo /path/to/project exec feature-a -- "$SHELL"

使用任意编辑器编辑 create 输出的 session-root/worktree 目录，在其中直接运行原生 Git：

    git status
    git diff
    git add .
    git commit -m "Implement feature"
    git checkout other-branch
    git rebase main

父项目工作目录仍可继续使用。session 拥有私有 Git 元数据、分支状态、index、未提交修改和构建输出，不会锁住父目录。

## 发布

publish 将 session 中已经提交的内容发布到 session 目标分支。它会先验证私有 commit closure，把缺失 object 导入 authority，再对目标 ref 执行 expected-old CAS。它不会创建 commit，也不会发布未提交文件。

    git vws --repo /path/to/project publish feature-a

支持新目标、相同 tip 和 fast-forward。如果其他 writer 在 CAS 前更新目标，命令返回冲突，并保持对方 ref 不变。请在 session 中 rebase 或 merge 后重试。若返回 recovery-required，说明 CAS 结果不能安全重放；保留 session 并运行 doctor。

## 删除与垃圾回收

正常删除干净 session：

    git vws --repo /path/to/project remove feature-a
    git vws gc

如果 tracked、untracked、ignored 或私有 Git 内容可能丢失，删除会被拒绝。--force 是明确的破坏性选项，仍不会绕过完整性或恢复检查。删除先进入 tombstone 状态，因此中断后的清理仍可诊断。

gc 会先做完整 census，只清理没有引用的 template、私有 object、session tombstone 和缓存快照。成功清理后可以重复运行。

## Doctor 与恢复

doctor 只检查已登记状态，不删除任何内容：

    git vws doctor
    git vws doctor | jq -c .

遇到 SESSION_RECOVERY_REQUIRED、PUBLISH_RECOVERY_REQUIRED、CACHE_RECOVERY_REQUIRED、GC_RECOVERY_REQUIRED、SESSION_CORRUPT 或其他非零结果时，立即停止破坏性操作。保留 $HOME/.git-vws 和 session root，通过 doctor 输出定位记录，不要手工删除状态文件。

忙碌 session 会被报告而不是强制 detach。先停止占用该 session 的编辑器、shell、编译器和子进程，再重试普通命令。

## 缓存操作

要安全复用昂贵但非 Git 数据的目录，先在 .vwscached 中列出目录，创建 session，在其中构建，并在 Git 干净后捕获：

    printf 'target/\nnode_modules/\n' > .vwscached
    git vws --repo . create build-a
    git vws --repo . exec build-a -- cargo build
    git vws --repo . cache build-a

快照不可变，每个新 session 都会得到独立的可写 COW 副本。缓存数据既不进入 commit，也不参与 publish。删除 session 后运行 git vws gc，可回收不再被任何 live session 引用的快照。

## 发布验证

下载归档和 SHA256SUMS，先核对归档摘要，再查看其中的 BUILD-METADATA.json。公开发布还包含 SPDX SBOM、第三方许可证清单和 PROVENANCE.sigstore.json。可以使用 GitHub CLI，结合 release notes 中记录的 source commit 与不可变 signer workflow，验证产物 attestation。
