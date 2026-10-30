# 架构与边界

## 多轮任务

`task_agent.py` 保存任务原文、用户补充、待执行候选与服务器确认的执行观察。`TaskPlanner` 每轮输出追问、下一步建议或总结，Guardrails AI 以独立任务结构校验，`task_scope.py` 根据用户原文限制工具目标与变更范围。执行仍复用原候选、审批和执行器。

工具结果作为非可信观察传回模型，不能授权变更。常见凭据按模式隐藏、证据长度有上限。任务显式获得只读授权后，后台连续执行低风险查询，变更或中高风险步骤暂停独立审批，获批后恢复。每步仍重新检查身份、范围与权限。模型总结不是独立事实验证。

HTTP API 默认通过 auth.py 登录会话获取身份，不接受请求字段指定角色。候选、任务与执行记录绑定用户，回滚单独检查角色及归属。默认执行环境为本地模拟器；显式指定诊断配置时使用本机只读采集器。参见 [登录与多步任务](AUTONOMOUS_TASKS.md)。

网页使用任务工作台、审批中心、工具调试与活动记录四个视图。`web/workbench.js` 只展示服务端状态：执行计数来自实际观察，计划与执行结果分开；不负责授权或决定是否执行。接口、角色、候选和审批校验仍由服务端完成。

## 候选生成

`POST /api/interpret` → `LocalSafetyApp.interpret()` → `NaturalLanguageInterpreter.interpret()`。

先检查输入长度并匹配硬规则；critical 直接拒绝。其余输入由 Guardrails AI 的 `PromptInjectionValidator` 和 `SensitiveInputValidator` 检查明确的注入与凭据模式，随后才调用默认 DeepSeek API。`model_client.py` 管理后端配置、官方 HTTPS 请求和错误处理，单步与多步共用。云端使用 JSON 输出模式，任务 Schema 放入提示；输出仍须经过 Pydantic 严格字段校验，再由 Guardrails 检查参数、敏感内容与请求一致性。确定性规则只覆盖已定义模式，不保证检测所有提示注入或模型错误。

规则风险与模型风险取高，参数预检通过后签发服务端候选 ID。候选包含工具、完整参数快照、摘要、风险、来源与过期时间，默认 900 秒；摘要不是原始参数的替代品。候选保存在内存，重启失效。

模型接口由 `model_client.py` 管理，可选择 DeepSeek、HTTPS Chat Completions 兼容服务或 Ollama。单步解释和多步规划共享同一份启动配置快照；不同服务的密钥不代用。状态接口返回实际加载的服务、模型、主机名与密钥是否配置，并对可检测的后续配置变更提示重启，不热切换进行中的任务。见 [模型配置](MODEL_CONFIGURATION.md)。

## 授权与执行

权限检查调用 `SecureToolService.check_call()` → `StructuredToolGateway.authorize()`。候选风险与工具风险继续取高，角色、参数或工具不合法会拒绝；需要审批的调用绑定具体候选、工具与参数摘要。

`LocalSafetyApp.execute()` 在锁内重新获取候选与权限。满足执行条件后先消费候选，再在需要审批时核验并消费审批令牌，最终 allow 才进入执行器。候选消费后失败也不会恢复，避免在结果不确定时盲目重试。

## 模拟器与恢复

虚拟路径 `/etc/myapp/test.conf` 映射到 `data/web_runtime/sandbox/etc/myapp/test.conf`。拒绝目录穿越、越出沙箱或工具允许目录的路径。服务状态保存到 `.services.json`，操作及变更前状态保存到 `.operations.json`。只有有恢复数据的操作能显式回滚。

这是应用级模拟环境，不是容器、虚拟机或任意代码隔离系统。check_disk 读取实际磁盘容量，其他工具操作沙箱文件和模拟服务数据。

## 真实本机只读诊断

`real_diagnostics.py` 根据维护者配置查询固定的 `127.0.0.1` 健康接口，读取精确映射的常规日志文件，并检查采集器所在磁盘。模型不能指定任意 URL 或宿主机文件路径。该后端拒绝重启、修改配置及回滚。

`diagnostic_reasoning.py` 区分服务端确认的事实、待验证线索与未知项，并根据健康检查和日志信号要求后续取证。HTTP 503、日志中的故障文本和磁盘容量可能相互不一致，不能把某条线索直接当作已确认根因。见 [配置与演示](REAL_DIAGNOSTICS.md)。

## 研究实验与产品主链

Guardrails AI 属于主链；NeMo 与 AgentDojo 的独立研究入口不在网页运行时调用。离线攻击测评不能等同于生产环境安全认证。
