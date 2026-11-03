# dsh-plugin-safety-check

给 DeepSeek Harness（DSH）用的**插件安装前静态安全审计**工具。它只读取 README、package.json、入口文件和代码，**不执行目标代码、不跑 npm install、不开子智能体**。

## 它回答什么

- 会把什么数据发到哪些网址？
- 会不会读本地文件、密钥、账号登录信息？
- 有没有加密/混淆后再执行的代码（eval / new Function / vm / 长 base64）？
- 安装时会不会自动下载或运行别的东西（preinstall/install/postinstall）？
- 装上以后会不会自己启动、自己发东西（listen / setInterval / cron / 网络钩子）？
- 身份是否对得上：同名作者、GitHub stars 与 npm 下载量、DSH 目录页的能力提醒。

## 快速使用

```bash
# GitHub 仓库
node scripts/audit.mjs --target https://github.com/owner/repo

# npm 包
node scripts/audit.mjs --target billion-context

# 本地目录（只读）
node scripts/audit.mjs --target ./some-plugin --no-network
```

输出：`audit-<slug>/report.md` 和 `report.json`，并在终端打印结论。

## 安装为 DSH Skill

把本仓库复制/软链到 DSH 技能目录：

```bash
# Windows
xcopy /E /I dsh-plugin-safety-check "%USERPROFILE%\.dsh\skills\dsh-plugin-safety-check"
# macOS / Linux
cp -r dsh-plugin-safety-check ~/.dsh/skills/
```

之后在 DSH 里说"审计这个插件"即可；`SKILL.md` 固化了检查清单和输出格式。

## 结论等级

- **HIGH**：安装脚本下载/执行、混淆后执行、读凭据并外发、来源不明二进制等 → 不建议装。
- **MEDIUM**：有外部网络、宽文件访问、自动启动/定时等，需要关设置或隔离。
- **LOW**：静态未发现高风险；仍需以实际运行/沙箱为准。

## 边界（重要）

这是**静态**审计，证据来自公开元数据与源码文本；它不能证明运行时绝对安全，也不会动态抓包。没有发现不等于没有风险。结论里会明确标"未验证"。

## 开发

```bash
npm test
```

测试使用本地夹具（safe / suspicious），不会联网执行任何目标代码。

## License

MIT
