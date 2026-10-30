# 模型服务配置

模型接口由后端配置，密钥不写进网页。支持 DeepSeek 官方 API、采用相同聊天协议的兼容 API，以及显式选择的 Ollama；每位使用者提供自己的服务账号和密钥。

## 使用其他兼容 API

将项目根目录的 `.env.example` 复制为 `.env`，选择 `openai_compatible` 并填写：

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://your-provider.example/v1
LLM_MODEL=your-model-id
LLM_API_KEY=
LLM_JSON_MODE=json_object
LLM_TOKEN_LIMIT_PARAM=max_tokens
LLM_TIMEOUT_SECONDS=30
LLM_MAX_TOKENS=4096
```

`your-provider.example` 和 `your-model-id` 都是占位符，必须替换为平台文档给出的 API 基础地址与可用模型 ID。把自己的密钥填写在本机 `.env` 的 `LLM_API_KEY=` 后面；示例和公开仓库中的密钥字段应一直为空。基础地址可带 `/v1` 或平台要求的其他路径，不能填写产品介绍网页地址。如果填写到 `/chat/completions`，程序会识别并避免重复拼接该路径。

该模式使用 HTTPS、Bearer 密钥、`POST /chat/completions`、`messages` 和非流式文本响应。响应需包含 `choices[0].message.content` 与正常的 `finish_reason`，模型内容必须是符合项目结构的 JSON。原生 Responses、Anthropic Messages、需要其他认证头或查询参数的接口不属于此适配范围；同一平台也可能有不支持该协议的模型。

不会自动读取 `DEEPSEEK_API_KEY` 或其他 SDK 的密钥作为替代，也不会把 DeepSeek 的专用 `thinking` 参数发送到其他平台。请只配置自己信任的服务地址：该服务将收到你配置的密钥、请求，以及按规则脱敏和截断后的任务证据。规则脱敏不能保证识别所有敏感信息。地址拒绝明文 HTTP、URL 凭据、查询参数和片段，不跟随重定向；网页和模型输出均不能修改地址。

## 两个兼容性选项

| 配置项 | 默认值 | 何时调整 |
| --- | --- | --- |
| `LLM_JSON_MODE` | `json_object` | 平台不接受 `response_format` 时改为 `prompt_only`，只在提示中要求 JSON |
| `LLM_TOKEN_LIMIT_PARAM` | `max_tokens` | 模型要求另一字段时改为 `max_completion_tokens` |

通用模式不发送固定温度或厂商专用推理选项。以上选项只调整请求协议，**不会关闭 Guardrails、严格结构校验、任务范围、权限或审批检查**。返回格式损坏、拒绝、截断或校验不通过时仍停止，不会为了成功而自动取消安全检查。

## 继续使用 DeepSeek

已有配置可继续使用，无需迁移密钥：

```dotenv
LLM_PROVIDER=deepseek
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-flash
DEEPSEEK_API_KEY=
```

DeepSeek 模式保留官方 HTTPS 域名限制和原有请求参数。详细说明见 [DeepSeek 配置](DEEPSEEK_API.md)。兼容模式的 `LLM_API_KEY` 与此模式的 `DEEPSEEK_API_KEY` 相互独立；切换模型服务必须配置对应密钥，不会自动跨服务使用。

## 选择 Ollama

显式设置 `LLM_PROVIDER=ollama`、`OLLAMA_MODEL` 和 `OLLAMA_URL`，并自行启动对应本地服务。该选择不读取云端密钥。项目不会在云端故障时自动切换到 Ollama。

## 如何确认切换已经生效

1. 修改后端环境变量或 `.env`。环境变量优先于 `.env`；如果同名环境变量仍在生效，只改文件不会覆盖它。
2. 停止并重新启动后端，运行中的任务不会自动换模型。重启会使旧会话和内存候选、任务失效。
3. 重新登录网页，查看顶部“当前生效”的服务、模型 ID 和服务主机名。

后端使用启动时的同一份配置快照处理单步请求与多步骤规划。状态接口只报告该快照，绝不返回密钥或完整服务 URL。网页约每 15 秒刷新状态；检测到可见配置变更时提示“重启后端后生效”，无效修改则提示当前仍使用已加载配置。状态检查不会调用付费模型。“配置已加载”或“密钥已配置”不代表已经验证网络、余额或模型可用性，需要实际请求另行验证。

环境变量属于进程启动环境，系统中后来改动的变量通常需重启进程后才能读取；网页无法检测所有进程外环境变更。不要仅通过刷新浏览器来切换后端模型。

## 常见问题

| 现象 | 检查 |
| --- | --- |
| 提示 `LLM_BASE_URL` 或 `LLM_MODEL` 未填写 | 补全兼容模式的必需配置，不要只换密钥 |
| 提示未配置 `LLM_API_KEY` | 当前选择的是兼容模式，DeepSeek 密钥不会被自动代用 |
| HTTP 400 | 核对模型、JSON 模式和 token 字段是否受平台支持 |
| HTTP 401 / 402 / 429 | 分别核对凭据、额度与限流；应用不会回显远端错误体 |
| 网页仍显示旧模型 | 核对环境变量优先级，确认已重启正确的后端进程并重新登录 |
| 新配置无效，旧配置仍显示 | 修正配置后重启，旧模型仍是实际生效值 |

协议依据：[Chat Completions 官方参考](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)。第三方兼容程度以其平台文档和实际受控验证为准，项目测试不等于已验证所有厂商。
