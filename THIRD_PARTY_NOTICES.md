# 第三方项目说明

原创代码采用根目录 [LICENSE](LICENSE) 中的 MIT 许可证，版权署名为 hjj061216。本文说明依赖和研究来源，不替代上游许可证，也不将第三方项目重新授权为本项目的 MIT 代码。

| 项目 | 本地记录版本 | 使用范围 | 上游 |
| --- | --- | --- | --- |
| Guardrails AI | 0.11.0 | 主链输入/输出验证框架，项目编写自定义运维验证器 | https://github.com/guardrails-ai/guardrails |
| Pydantic | 由 Guardrails AI 依赖安装 | 原始候选 JSON 严格结构校验 | https://github.com/pydantic/pydantic |
| PyYAML | 6.0.3 | 读取策略和工具白名单 | https://github.com/yaml/pyyaml |
| NeMo Guardrails | 0.24.1 | 本地研究独立围栏实验，不属于导出的网页主链 | https://github.com/NVIDIA/NeMo-Guardrails |
| AgentDojo | 0.1.35 | 本地研究离线任务与攻击样本来源，不属于导出的网页主链 | https://github.com/ethz-spylab/agentdojo |

发布包不打包上述项目的虚拟环境或安装源码。通过安装步骤下载的依赖保持其各自许可；依赖包内的许可证与版权声明仍适用。后续如复制上游源码、任务数据或攻击样本，应先检查对应文件的许可与声明要求，并随分发内容保留必要声明。NeMo / AgentDojo 历史实验不在当前精简发布包中。
