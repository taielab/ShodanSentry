# ShodanSentry

![ShodanSentry](https://img.shields.io/badge/Security-CVE%20Scanner-blue)
![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-green)
![License MIT](https://img.shields.io/badge/License-MIT-yellow)

一个用于使用 Shodan API 和 NVD API 扫描和分析 CVE 的高级安全工具。该工具支持大规模资产漏洞扫描，自动翻译漏洞信息，并提供详细的安全分析报告。

## 📋 功能特点

- **Shodan 资产发现**：使用强大的 Shodan 搜索语法识别互联网上的资产
- **NVD 漏洞查询**：实时查询美国国家漏洞数据库获取漏洞详情
- **多语言支持**：自动将漏洞描述翻译成中文（支持多种翻译服务自动切换）
- **智能缓存**：缓存查询结果以提高性能并减少 API 调用
- **并发处理**：高效的并发处理以加速大规模扫描
- **断点恢复**：支持中断后从断点继续扫描
- **GitHub 利用脚本识别**：自动搜索漏洞相关的 GitHub 利用代码
- **AI 增强分析**：使用 GPT 分析漏洞，提供额外的安全见解
- **导出格式化报告**：以 CSV 格式导出详细的漏洞报告

## 🔧 安装方法

### 前提条件

- Python 3.7 或更高版本
- Shodan API 密钥
- NVD API 密钥 (可选但推荐)
- GitHub 令牌 (可选)
- OpenAI API 密钥 (可选)

### 安装步骤

1. 克隆仓库：

```bash
git clone https://github.com/username/ShodanSentry.git
cd ShodanSentry
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

或者使用 setup.py 安装：

```bash
pip install -e .
```

3. 配置 API 密钥：

复制并修改配置文件：

```bash
cp config.yaml.example config.yaml
```

然后编辑 `config.yaml` 文件，添加您的 API 密钥和配置选项。

## ⚙️ 配置

配置文件 `config.yaml` 包含以下主要部分：

```yaml
# Shodan API配置
api:
  key: "YOUR_SHODAN_API_KEY"
  base_url: "https://api.shodan.io"
  timeout: 120

# 搜索配置
search:
  query: "org:'Target Organization'"
  limit: 100

# NVD API配置
nvd:
  api_key: "YOUR_NVD_API_KEY"
  rate_limit: 50
  batch_size: 10
  concurrent_requests: 5
  cache_ttl: 86400

# 其他可选配置
# ...
```

### 配置选项说明

- **api**: Shodan API 配置
  - `key`: Shodan API 密钥
  - `timeout`: 请求超时时间（秒）

- **search**: 搜索配置
  - `query`: Shodan 搜索查询语句
  - `limit`: 要处理的页数限制

- **nvd**: NVD API 配置
  - `api_key`: NVD API 密钥
  - `rate_limit`: 速率限制（每 30 秒的请求数）
  - `batch_size`: 批量请求大小
  - `concurrent_requests`: 并发请求数

- **openai**: OpenAI 配置（可选）
  - `api_key`: OpenAI API 密钥
  - `base_url`: API 基础 URL
  - `model`: 模型名称

- **github**: GitHub 配置（可选）
  - `token`: GitHub API 令牌

- **output**: 输出配置
  - `csv_headers`: CSV 输出字段

## 🚀 使用方法

执行扫描：

```bash
python cve_stats.py
```

或者如果已经通过 setup.py 安装：

```bash
cve-scanner
```

### 示例用法

1. **扫描特定组织的资产**：

```yaml
# 在 config.yaml 中
search:
  query: "org:'Example Corp'"
  limit: 10
```

2. **扫描特定端口或服务**：

```yaml
search:
  query: "port:80 http"
  limit: 5
```

3. **扫描特定国家的资产**：

```yaml
search:
  query: "country:CN org:'Example Corp'"
  limit: 10
```

## 📊 输出示例

扫描结果将保存在 `cve_simple_stats.csv` 文件中，包含以下信息：

- 查询语句
- CVE 编号
- 影响资产数量
- 漏洞已验证状态
- 漏洞名称
- 漏洞描述（英文和中文）
- 严重程度和 CVSS 分数
- 受影响的软件配置
- 参考信息
- 发布和修改日期

## 📝 日志

扫描过程中的日志信息将保存在 `cve_scan.log` 文件中，同时会在控制台显示。日志包含扫描进度、API 调用状态和错误信息等。

## 🔄 缓存管理

工具会自动缓存 NVD API 响应和翻译结果以提高性能：

- CVE 详情缓存有效期：1 天
- 翻译结果缓存有效期：7 天

缓存数据保存在 `./cve_cache` 目录中。如需清除缓存，只需删除该目录。

## ⚠️ 注意事项

- 请注意遵守 Shodan、NVD、OpenAI 和 GitHub 的服务条款和 API 使用限制
- 对于大规模扫描，建议增加 `limit` 值并确保有足够的 API 配额
- 该工具适用于合法的安全评估和研究目的

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- [Shodan](https://www.shodan.io/) - 互联网设备搜索引擎
- [NVD](https://nvd.nist.gov/) - 国家漏洞数据库
- 所有用于翻译的服务
