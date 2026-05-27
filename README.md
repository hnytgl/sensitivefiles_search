# sensitivefiles_search

本工具用于在本机或授权目录中快速排查敏感文件、密钥、弱密码、连接串和个人信息线索。适合代码审计前的自查、项目交付前的泄露检查、CTF/靶场环境中的本地敏感信息梳理。

> 请只在你拥有授权的目录中使用。工具默认会对命中内容脱敏，减少二次泄露风险。

## 功能特点

- 自动递归扫描目录，也支持直接扫描单个文件。
- 默认识别常见敏感文件类型，包括 `.env`、`.npmrc`、`.netrc`、`.kubeconfig`、`.pem`、`.key`、`.tfvars`、`.properties`、`.yaml`、`.json`、`.sql`、`.log` 等。
- 内置规则覆盖弱密码、账号密码关键词、API Key、GitHub Token、Slack Token、AWS Access Key、私钥、JWT、数据库连接串、JDBC、IP、邮箱、身份证号、手机号。
- 支持自定义关键词、扩展名、排除目录、排除通配符和最大文件大小。
- 支持多线程扫描，适合较大的代码目录。
- 默认脱敏输出，可按需关闭。
- 支持 `txt`、`json`、`csv`、`html` 四种报告格式。
- 控制台输出更友好，会显示扫描进度、风险分布和重点命中结果。
- 发现敏感信息时返回退出码 `1`，可接入 CI 做泄露拦截。

## 环境要求

- Python 3.10+
- 无第三方依赖

## 快速开始

扫描当前目录：

```bash
python sensitivefiles_search.py .
```

扫描指定目录并生成 HTML 报告：

```bash
python sensitivefiles_search.py /path/to/project --format html -o report.html
```

扫描所有文件类型：

```bash
python sensitivefiles_search.py . --all-files
```

指定扩展名：

```bash
python sensitivefiles_search.py . --ext .env,.yaml,.json,.py
```

添加自定义关键词：

```bash
python sensitivefiles_search.py . -k internal_secret
```

排除目录和文件：

```bash
python sensitivefiles_search.py . --exclude-dir node_modules,dist --exclude-glob "*.min.js"
```

关闭脱敏输出：

```bash
python sensitivefiles_search.py . --no-redact
```

## 常用参数

| 参数 | 说明 |
| --- | --- |
| `paths` | 要扫描的文件或目录，可传多个；不传时进入交互输入 |
| `-o, --output` | 报告输出路径，默认 `sensitive_info_results.txt` |
| `--format` | 报告格式：`txt`、`json`、`csv`、`html` |
| `--ext` | 指定扫描扩展名，逗号分隔 |
| `--all-files` | 扫描所有文件类型 |
| `--exclude-dir` | 排除目录名，逗号分隔 |
| `--exclude-glob` | 排除文件通配符，可重复传入 |
| `--max-size-mb` | 单文件最大大小，默认 `5` |
| `-t, --threads` | 扫描线程数，默认使用 CPU 核心数 |
| `-C, --context` | 报告中展示命中上下文行数，默认 `2` |
| `-k, --keyword` | 额外自定义关键词 |
| `--no-redact` | 不脱敏输出命中内容 |
| `--quiet` | 减少控制台输出 |
| `--no-color` | 禁用彩色输出 |

## 示例输出

```text
扫描完成
  扫描文件：128
  发现结果：3
  耗时：0.42s
  风险分布：严重 1 / 高 1 / 中 1 / 低 0
  [严重] 私钥 /project/id_rsa:1 -> ----************************KEY-----
  [高] 弱密码 /project/.env:3 -> pass********3456
  [中] 凭据关键词 /project/config.ini:8 -> user********admin
报告已保存：sensitive_info_results.txt
```

## 安全说明

- 默认报告会对命中的敏感片段做脱敏处理。
- 如果使用 `--no-redact`，报告可能包含真实密钥、密码或个人信息，请妥善保存。
- 本工具是本地排查工具，不会上传扫描内容。
- 规则匹配存在误报和漏报，请结合人工复核使用。

## 开发测试

```bash
python -m pytest
```

