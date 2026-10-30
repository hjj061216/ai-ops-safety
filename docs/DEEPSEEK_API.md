# DeepSeek API 配置

本文针对 DeepSeek 官方接口。其他服务可以选择独立的兼容模式，见 [模型服务配置](MODEL_CONFIGURATION.md)；不能只把其他平台密钥填进 `DEEPSEEK_API_KEY`。

默认模型为 DeepSeek-V4.1-Flash，对应官方 API 参数 `deepseek-flash`。项目使用 Python 标准库调用 `https://api.deepseek.com/chat/completions`，无需安装模型或新增 SDK。

## 配置与启动

1. 如已有环境变量 `DEEPSEEK_API_KEY`，后端直接使用它。
2. 或将根目录 `.env.example` 复制为 `.env`，填写 `DEEPSEEK_API_KEY`。不要将密钥贴入网页、聊天或提交到仓库。
3. 环境变量优先于 `.env`，更改后重新启动后端。双击 `run-local-app.bat` 可启动控制台；若旧后端仍在运行，需要先关闭旧服务再启动。
4. 重启后端并重新登录后，工作台显示当前生效的 `DeepSeek API · deepseek-flash` 和主机名。修改尚未生效时会提示重启；执行标识按配置显示“本地模拟”或“真实只读”，与模型来源分开。

`.env` 支持 `变量名=值`、配对单/双引号以及单独一行的 `#` 注释；不展开变量、不执行命令、不支持多行密钥。只接受项目声明的模型配置项。源码导出器只带空密钥的 `.env.example`。

## 输出与安全

默认关闭 thinking、temperature 设为0、输出上限4096 token、每次请求超时30秒。DeepSeek 使用 `response_format={"type":"json_object"}`；它保证 JSON 格式，不保证满足项目字段与任务范围。任务 Schema 放入系统提示，返回值仍必须通过 Guardrails AI、服务端范围校验与网关授权。不会把 Ollama 专用 `format` 参数发送到 DeepSeek。

用户输入先通过安全检查，再发送到 DeepSeek。多步规划还会发送任务范围和经过截断、常见凭据遮盖的执行结果摘要；规则遮盖不保证删除全部敏感内容。API 密钥仅在发往官方 HTTPS 地址的 Authorization 中使用，不发送给模型消息、不出现在网页状态或错误体中。客户端不跟随重定向。

云端模型负责生成候选和分析，不直接执行工具。默认模拟模式中的重启、配置修改和恢复只改变本地演示数据；显式启用的真实只读模式查询配置中的本机健康接口与日志，拒绝全部变更操作。项目不提供任意 Shell 或远程服务器控制。

## 常见故障

| 提示 | 处理方式 |
| --- | --- |
| 未配置 DEEPSEEK_API_KEY | 在后端环境变量或 .env 中填写，重启后端 |
| HTTP 401 | 检查是否为有效的 DeepSeek 官方 API 密钥 |
| HTTP 402 | 检查账户余额与额度；充值后重新创建任务即可 |
| HTTP 429 | 等待限流恢复，避免连续重复提交 |
| 连接失败或超时 | 检查网络；确有需要时调整 LLM_TIMEOUT_SECONDS |
| 输出被截断 | 缩短任务/配置内容，或调整 LLM_MAX_TOKENS 后重启 |
| Guardrails 验证失败 | 核对请求、目标与参数；不得为了成功执行而关闭校验 |

接口故障不会自动启动或调用 Ollama。单步入口仅保留原有明确只读规则兜底，多步任务停止并保留证据。截断、损坏输出与安全验证失败不能触发兜底执行。

旧研究脚本如需本地模型，可显式设置 `LLM_PROVIDER=ollama`，配合 `OLLAMA_MODEL`、`OLLAMA_URL`；新安装默认仍为 DeepSeek。

## 官方参考

- 模型与地址：https://api-docs.deepseek.com/quick_start/agent_integrations/
- JSON 模式：https://api-docs.deepseek.com/guides/json_mode/
- 接口字段：https://api-docs.deepseek.com/api/create-chat-completion/
