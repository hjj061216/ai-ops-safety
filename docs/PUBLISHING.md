# 准备 GitHub 发布包

源码采用 [MIT 许可证](../LICENSE)，版权署名为 `hjj061216`。第三方依赖的授权见 [第三方说明](../THIRD_PARTY_NOTICES.md)。本项目定位为工具调用安全控制参考实现，发布源码不代表已经验证生产部署或任意远程运维能力。

## 1. 验证干净的源码副本

需要 Python 3.12、Node.js，以及下载依赖所需的网络连接。在开发目录执行：

```bash
python scripts/verify_release.py --output dist/release-check
```

脚本会：

1. 将允许的源码与公开文档导出到一个新目录，拒绝覆盖已有目录。
2. 在副本中创建全新的核心和 Guardrails AI 虚拟环境。
3. 在副本中运行真实 Guardrails 验证演示，再运行整套单元、HTTP 和页面脚本测试。

验证进程移除继承的模型设置和密钥，不使用开发目录的 Guardrails 环境，不需要真实 API 密钥。测试使用固定模型返回值或受控 HTTP 响应，不调用付费模型或变更真实服务。出现跳过项时，应检查对应环境是否缺失；退出码为零并不证明被跳过的能力已经验证。

验证目录含虚拟环境、测试生成数据，**不要将该目录作为发布包上传**。保留日志以便定位问题；再次验证时请指定另一个新目录。脚本不会删除或覆盖旧目录。

GitHub Actions 在 Windows / Linux 上运行同一个脚本，检查的是导出副本。提交后查看仓库 Actions 页；工作流文件存在不等于远端已经通过。

## 2. 生成单独的源码发布包

验证通过后，在开发目录运行：

```bash
python scripts/export_github.py --output dist/ai-ops-safety-v0.1.1
```

输出目录必须不存在。脚本只复制明确允许的应用源码、策略、MIT 许可证、公开指南、界面示例以及测试与夹具，不复制内部设计记录、虚拟环境、账号数据库、审批令牌、审计数据、PPT、历史实验或 `.env`。

公开指南和图片在 `scripts/export_github.py` 的 `FILES` 中逐个列出；新增内部文档不会自动公开。测试目录允许的 Python / JavaScript 文件会随包复制，因此发布前也应检查测试数据只包含合成示例。

检查发布包的 `SOURCE_MANIFEST.json`，其中列出每个文件的 SHA-256。源码修改后应重新验证和导出，避免上传旧副本。导出器只控制文件范围，不能替代对文件内容中真实凭据、署名及第三方来源的检查。

## 3. 试用与上传

在发布包中按 README 安装、创建自己的账号并配置自己的模型密钥；没有通用默认账号或密码。默认模式使用本地模拟数据，真实只读诊断需按指南显式启用。真实模型的回答质量需要单独试用，固定响应测试不等于模型能力评估。

上传时进入上述**源码发布目录**，而不是混有研究材料的开发目录，也不是 `release-check` 验证目录。初始化本地仓库：

```bash
git init
git add .
git status --short
git commit -m "Prepare AI operations safety reference implementation"
git branch -M main
```

确认暂存内容符合清单后，再关联自己选择的 GitHub 仓库并推送。这里不预设仓库名，也不会替你创建或公开仓库。

如果在发布目录运行过应用或测试，Git 操作仍应检查 `.gitignore` 和暂存内容；不要把验证后的整个目录直接拖进网页上传。真正的发布目录应只包含源码清单中的文件和 `SOURCE_MANIFEST.json`。
