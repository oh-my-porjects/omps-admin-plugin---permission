# 权限公共模块

- 项目后台唯一事实源是 `admin-intents.yaml` 与 `api-docs/`；后台实际页面由 V4 编译器生成。
- 禁止恢复 `admin-web.yaml`、`AdminWebHint`、旧 spec 存储或浏览器自由拼接请求。
- 任何权限字段、绑定接口或安全约束变更，必须同步更新接口文档、默认意图与测试。
- 没有已验证的批量查询能力时，不得把 ID 渲染为伪造的关联名称；必须新增真实能力后再声明 relationship。
