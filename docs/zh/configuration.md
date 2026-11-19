# 配置

[中文](configuration.md) | [English](../en/configuration.md) | [返回中文首页](../../README.md)

git-vws 的运行状态统一保存在 $HOME/.git-vws。插件本身没有额外的常驻配置文件；单仓库命令通过 --repo 指定 authority，省略时使用当前目录。

## 仓库选择

init 接受现有 bare 仓库、普通项目目录或项目的 .git 目录。普通项目会按规范化后的 .git 路径登记。authority 必须是单一 Git 目录：git-dir 与 common-dir 相同，且不能已有 linked-worktree 注册目录或 object alternates。

    git vws init /path/to/project
    git vws init /path/to/repository.git
    git vws --repo /path/to/project create feature-a

list --all、doctor 和 gc 作用于所有已登记 authority，不能与 --repo 同时使用。

## 创建选项

    git vws create NAME [--from REV] [--target BRANCH] [--path MANAGED_PATH]

NAME 是本地 session 名称；未指定 --target 时也作为发布目标分支。--target 选择其他分支，--from 选择起始 commit。两者都省略时，优先使用已有目标分支 tip；目标不存在时使用 authority 的 HEAD。

--path 是面向恢复和拓扑检查的高级断言，必须等于 git-vws 实际管理的 session root，不是通用的自定义输出目录选项。

## 非 Git 缓存清单

.vwscached 是可选的项目文件，方向故意与 .gitignore 相反：每个非空、非注释行声明一个要捕获和复用的仓库相对目录。

    # .vwscached
    target/
    node_modules/
    .gradle/

解析器只接受字面路径。路径不能是绝对路径，不能含 glob 字符，不能命名 .git 或 .vwscached，不能逃出项目目录，不能与其他条目重叠，也不能指向普通文件。目录不存在时记录为空选择，不会用旧快照顶替。

缓存键包含 authority 身份、base commit、配置文件完整字节、配置路径、内容摘要和状态根所在 volume，避免缓存跨仓库、跨 commit、跨配置版本或跨不兼容存储卷复用。

## 缓存生命周期

添加 .vwscached 后创建 session，在普通 worktree 中构建，并且只在 Git 干净时捕获：

    git vws --repo . create build-cache
    git vws --repo . exec build-cache -- cargo build
    git vws --repo . cache build-cache

捕获的树会被封存为不可变快照。之后创建的 session 得到自己的可写 native-COW 副本。缓存目录通过 session 私有的 core.excludesFile 排除在 Git status 外，不进入 commit，也不会被 publish 发布。

git vws cache 会拒绝 dirty Git 状态、不安全条目和不一致 receipt。git vws gc 只删除完整 session census 证明没有引用的快照。

## 存储要求

状态根和所有 native-COW 树必须位于同一个受支持的 volume。macOS 要求 APFS，并使用系统 clone 原语；Linux 要求 FICLONE 以及可验证共享 extent 的 FIEMAP 结果。不支持的文件系统返回 STORAGE_UNSUPPORTED，不会静默退化为完整复制。

Linux 上的实测结论：

| 文件系统 | 是否支持 | 说明 |
| --- | --- | --- |
| XFS | 支持 | 需以 `mkfs.xfs -m reflink=1` 创建 |
| btrfs | 支持 | 原生 reflink |
| **ext4** | **不支持** | 内核未实现 reflink，`FICLONE` 返回 `EOPNOTSUPP`（errno 95） |
| tmpfs / NFS / overlayfs | 不支持 | 无 reflink 能力 |

`init` 不检测存储能力；第一次 `create` 触发 COW 探测时才失败。

## 在 ext4 上使用 loop 状态根

若宿主只有 ext4，可以用一次性的 root 权限把状态根放到一个稀疏 btrfs 镜像里：

    sudo git vws setup-loop --size 8G
    sudo git vws setup-loop --size 8G --adopt   # 把已有 $HOME/.git-vws 迁进镜像
    git vws doctor

镜像文件默认 `$HOME/.git-vws.img`，表观 8G 但初始只占几 MB，按写入量增长。命令会挂载到 `$HOME/.git-vws` 并写入 `/etc/fstab`，因此重启后自动恢复；此后的所有命令都以普通用户身份运行，不需要再提权。

扩容在原地完成，不需要卸载：

    sudo git vws loop-resize --size 16G

`--adopt` 会把原有状态根复制进镜像，并保留 `$HOME/.git-vws.pre-loop` 作为回退，不销毁数据。镜像未挂载时 `doctor` 会提示先执行 `mount`。

当前版本拒绝 LFS、submodule、sparse 或 partial clone、clean/smudge filter，以及不支持的 ACL、xattr、file flag、特殊文件或 hard link 组合。

## 名称与机器输出

Session 名称按操作系统字节处理。普通场景直接使用名称；exec、cache 和 remove 也支持 --name-hex，用于精确指定小写十六进制字节序列。list、doctor 和 gc 输出 NDJSON，便于脚本逐行处理。
