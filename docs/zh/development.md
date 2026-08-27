# 开发与发布

[中文](development.md) | [English](../en/development.md) | [返回中文首页](../../README.md)

git-vws 是 Rust 2021 项目，最低支持 Rust 1.85。二进制以 Git Extension 形式工作：Git 通过 PATH 找到外部 git-vws，从而提供 git vws 子命令。实现不 fork Git，不改变 Git object 格式，也不依赖 daemon。

## 代码布局

| 路径 | 职责 |
| --- | --- |
| src/main.rs | CLI 解析、帮助信息、退出码和命令分发。 |
| src/authority.rs | authority 登记、状态根、记录事务和身份校验。 |
| src/git.rs | 隔离 Git 进程执行、输出限制和直接子进程处理。 |
| src/template.rs | 不可变 Git tree 模板和模板维护。 |
| src/storage.rs | native COW、文件身份、extent 检查、封存和受管树清理。 |
| src/session.rs | session 生命周期、linked-worktree 元数据、publish CAS、维护和租约。 |
| src/cache.rs | .vwscached 解析、不可变快照、缓存物化和缓存 GC。 |
| tests/ | authority、生命周期、Git parity、发布、维护和缓存集成测试。 |
| .github/workflows/ | 质量检查、原生文件系统验证和发布。 |

## 本地质量门禁

提交前运行与 CI 同类的完整检查：

    cargo fmt --all -- --check
    cargo check --locked --all-targets
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked --all-targets -- --test-threads=1
    cargo build --locked --release

native COW 测试必须在目标文件系统上运行。在不支持的 volume 上本地通过，不能替代 macOS APFS 或 Linux reflink 发布门禁证据。

## 变更约定

Git 操作必须保持原生且对用户可见。新增状态必须有明确 record、身份绑定、清理路径和恢复语义。禁止加入 scan-and-adopt 回退、完整复制回退、第二套可变真相或新的 daemon。

修改 .vwscached 时需要覆盖解析、scope 隔离、快照封存、session 独立修改、status 排除、dirty capture 拒绝、源目录缺失和安全 GC。修改 publish 时必须保留 expected-old CAS，不能重置或覆盖已被其他 writer 修改的目标。

每个面向用户的命令都必须让 git vws -h 及命令级帮助对人和自动化都足够可用。稳定错误码和 NDJSON 字段属于接口契约。

## CI

CI 在 Linux 上运行格式化、编译、Clippy 和测试，随后在原生 runner 上验证 macOS APFS 与 Linux reflink 行为。原生任务会检查 Git 源码契约、文件系统身份、COW 证据、生命周期测试、publish 行为、缓存清理和 checkpoint-only 标记缺失。Linux 发布构建使用 musl。

发布流程构建 x86_64 与 ARM64 macOS 产物，以及 x86_64 静态 Linux 产物。Windows 不在当前发布范围内。

## 发布流程

发布版本必须同时存在于 Cargo.toml 和 Cargo.lock。发布 tag 必须是 annotated semantic-version tag，与 package 版本一致，并且指向 main push CI 成功的精确 commit。tag annotation 记录 source commit 和发布前 CI run 身份。

    git tag -a v1.0.3 -m "git-vws v1.0.3"
    git push origin main
    git push origin v1.0.3

GitHub Actions 会生成确定性归档、SHA256SUMS、SPDX 2.3 SBOM、第三方许可证清单、构建元数据和公共 Sigstore provenance bundle。source commit 的完整 CI 通过前不要推送 tag。

## 文档维护

根目录 README.md 是中文入口。docs/en/ 与 docs/zh/ 一一对应，并保持相同文件名。命令行为、存储范围、支持平台或发布产物发生变化时，需要同步更新两种语言。
