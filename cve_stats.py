import shodan
import csv
import yaml
import time
import requests
import openai
from translate import Translator
from github import Github
import concurrent.futures
import os
import json
from ratelimit import limits, sleep_and_retry
import logging
from datetime import datetime
from functools import partial
import diskcache
from googletrans import Translator as GoogleTranslator
import translators as ts

class CVEStats:
    def __init__(self, config_path='config.yaml'):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cve_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.config = self._load_and_validate_config(config_path)
        self.api = shodan.Shodan(self.config['api']['key'])
        
        # 初始化多个翻译器以轮换使用
        self.translators = [
            Translator(to_lang='zh'),
            Translator(from_lang='en', to_lang='zh-CN')
            # Translator(from_lang='en', to_lang='zh-TW')
        ]
        self.current_translator = 0
        
        # 配置OpenAI
        openai.api_key = self.config['openai']['api_key']
        openai.api_base = self.config['openai']['base_url']
        
        # GitHub配置是可选的
        if 'github' in self.config and self.config['github'].get('token'):
            self.github = Github(self.config['github']['token'])
        else:
            self.github = None
        
        self.cache = diskcache.Cache('./cve_cache')
        
        # 调整翻译服务顺序，把MyMemory放到最后
        self.translation_services = [
            self._translate_google,
            self._translate_bing,
            self._translate_baidu,
            self._translate_mymemory  # 放到最后
        ]
        
    def _load_and_validate_config(self, config_path):
        required_fields = {
            'api': ['key'],
            'cve': ['timeout'],
            'search': ['query']
        }
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        for section, fields in required_fields.items():
            if section not in config:
                raise ValueError(f"配置缺少 {section} 部分")
            for field in fields:
                if field not in config[section]:
                    raise ValueError(f"配置缺少 {section}.{field}")
                
        return config
    
    def translate_text(self, text):
        """带缓存的翻译"""
        if not text:
            return "无内容"
        
        # 检查缓存
        cache_key = f'trans_{hash(text)}'
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        try:
            result = self._try_translate(text)
            # 存入缓存
            self.cache.set(cache_key, result, expire=86400*7)  # 7天过期
            return result
        except Exception as e:
            self.logger.error(f"翻译失败: {str(e)}")
            return f"{text} (翻译失败)"

    def _try_translate(self, text):
        """尝试使用当前翻译器翻译，失败则尝试下一个"""
        try:
            # 分段处理长文本
            max_length = 1000  # 增加单次翻译长度，减少请求次数
            if len(text) <= max_length:
                return self.translation_services[self.current_translator](text)
            
            # 处理长文本
            parts = [text[i:i+max_length] for i in range(0, len(text), max_length)]
            translated_parts = []
            
            for part in parts:
                translated_part = self.translation_services[self.current_translator](part)
                translated_parts.append(translated_part)
                time.sleep(0.5)  # 减少延迟
                # 轮换翻译器
                self.current_translator = (self.current_translator + 1) % len(self.translation_services)
                
            return ' '.join(translated_parts)
            
        except Exception as e:
            self.logger.warning(f"翻译失败，尝试下一个翻译器: {str(e)}")
            return self._try_next_translator(text)

    def _translate_mymemory(self, text):
        """使用MyMemory翻译"""
        try:
            translator = Translator(to_lang='zh')
            return translator.translate(text)
        except:
            return self._try_next_translator(text)

    def _translate_google(self, text):
        """使用Google翻译"""
        try:
            translator = GoogleTranslator()
            return translator.translate(text, dest='zh-cn').text
        except:
            return self._try_next_translator(text)

    def _translate_bing(self, text):
        """使用Bing翻译"""
        try:
            return ts.bing(text, from_language='en', to_language='zh')
        except:
            return self._try_next_translator(text)

    def _translate_baidu(self, text):
        """使用百度翻译"""
        try:
            return ts.baidu(text, from_language='en', to_language='zh')
        except:
            return self._try_next_translator(text)

    def _try_next_translator(self, text):
        """如果当前翻译器失败，尝试下一个"""
        original_translator = self.current_translator
        
        for _ in range(len(self.translation_services) - 1):
            self.current_translator = (self.current_translator + 1) % len(self.translation_services)
            try:
                return self.translation_services[self.current_translator](text)
            except Exception as e:
                self.logger.warning(f"翻译器 {self.current_translator} 失败: {str(e)}")
                continue
            
        # 如果所有翻译器都失败，重置为原始翻译器
        self.current_translator = original_translator
        return f"{text} (翻译失败)"
    
    def analyze_cve_with_gpt(self, cve_id, description):
        """使用GPT分析CVE"""
        try:
            prompt = f"""分析以下CVEa:
CVE ID: {cve_id}
描述: {description}

请提供以下信息:
1. 漏洞简要分析
2. 可能的攻击场景
3. 建议的缓解措施
4. 漏洞利用难度评估
5. 修复建议

请用中文回答。
"""
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "你是一个安全专家，专门分析CVE漏洞。"},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"GPT分析失败: {e}")
            return "分析失败"
            
    @sleep_and_retry
    @limits(calls=30, period=60)  # 30 calls per minute
    def search_github_exploits(self, cve_id):
        """搜索GitHub上的相关利用脚本"""
        if not self.github:
            return []
        
        try:
            # 优化搜索查询
            queries = [
                f'"{cve_id}" in:readme,description',  # 使用精确匹配
                f'"{cve_id}" filename:*.py filename:*.go filename:*.rb filename:*.pl',  # 在特定文件类型中搜索
                f'"{cve_id}" path:/ path:/exploit path:/poc'  # 在特定路径下搜索
            ]
            
            all_results = {}
            
            for query in queries:
                try:
                    self.logger.info(f"搜索GitHub: {query}")
                    repos = self.github.search_repositories(query, sort="updated", order="desc")
                    
                    if not repos or repos.totalCount == 0:
                        self.logger.info(f"未找到结果: {query}")
                        continue
                    
                    for repo in repos[:5]:  # 限制每个查询最多5个结果
                        if repo.html_url in all_results:
                            continue
                        
                        try:
                            # 检查仓库活跃度
                            if (datetime.now() - repo.updated_at).days > 365:  # 超过1年未更新的跳过
                                continue
                            
                            # 智能识别相关文件
                            relevant_files = []
                            try:
                                contents = repo.get_contents("")
                                while contents:
                                    file_content = contents.pop(0)
                                    
                                    if file_content.type == "dir":
                                        contents.extend(repo.get_contents(file_content.path))
                                    else:
                                        file_lower = file_content.name.lower()
                                        if any(keyword in file_lower for keyword in [
                                            'exploit', 'poc', 'exp', 'payload', 'attack', 
                                            cve_id.lower(), 'vulnerability'
                                        ]):
                                            relevant_files.append({
                                                'name': file_content.name,
                                                'path': file_content.path,
                                                'type': file_content.type
                                            })
                                        
                            except Exception as e:
                                self.logger.warning(f"获取文件列表失败: {e}")
                                continue
                            
                            if relevant_files or repo.name.lower().startswith(cve_id.lower()):
                                all_results[repo.html_url] = {
                                    'name': repo.name,
                                    'url': repo.html_url,
                                    'description': repo.description or "无描述",
                                    'stars': repo.stargazers_count,
                                    'last_updated': repo.updated_at.strftime('%Y-%m-%d'),
                                    'language': repo.language or "未知",
                                    'relevant_files': relevant_files
                                }
                            
                        except Exception as repo_error:
                            self.logger.warning(f"处理仓库失败: {repo_error}")
                            continue
                        
                    time.sleep(2)  # 降低请求频率
                    
                except Exception as query_error:
                    self.logger.error(f"执行查询失败: {query_error}")
                    continue
            
            # 结果排序和过滤
            sorted_results = sorted(
                all_results.values(),
                key=lambda x: (x['stars'], len(x['relevant_files'])),
                reverse=True
            )
            
            # 格式化返回结果
            return [{
                'name': r['name'],
                'url': r['url'],
                'description': r['description'],
                'stars': r['stars'],
                'last_updated': r['last_updated'],
                'language': r['language'],
                'exploit_files': '; '.join(f"{f['path']}" for f in r['relevant_files'])
            } for r in sorted_results[:5]]  # 只返回最相关的5个结果
            
        except Exception as e:
            self.logger.error(f"GitHub搜索失败: {str(e)}")
            return []

    def get_cve_details(self, cve_id):
        """获取CVE详情"""
        # 检查缓存
        cache_key = f'cve_{cve_id}'
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            self.logger.info(f"从缓存获取 {cve_id}")
            return cached_result
        
        max_retries = 3
        base_delay = 2
        
        headers = {
            'User-Agent': 'CVE-Research-Tool/1.0',
            'Accept': 'application/json',
        }
        
        # 检查NVD API密钥配置
        if 'nvd' not in self.config or 'api_key' not in self.config['nvd']:
            self.logger.error("未配置NVD API密钥，请在config.yaml中添加nvd.api_key配置")
            return self._get_empty_cve_details()
        
        headers['apiKey'] = self.config['nvd']['api_key']
        
        session = requests.Session()
        # 配置重试策略
        retry_strategy = requests.adapters.Retry(
            total=max_retries,
            backoff_factor=base_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,  # 增加连接池大小
            pool_maxsize=20,
            pool_block=False
        )
        session.mount("https://", adapter)
        
        # 优化超时设置
        timeout = (5, self.config['cve']['timeout'])  # (连接超时, 读取超时)
        
        for attempt in range(max_retries):
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                
                # 指数退避延迟
                if attempt > 0:
                    delay = base_delay * (2 ** attempt)
                    self.logger.info(f"等待 {delay} 秒后重试...")
                    time.sleep(delay)
                
                response = session.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=True
                )
                
                self.logger.info(f"NVD API响应状态: {response.status_code}")
                
                if response.status_code == 200:
                    result = self._parse_nvd_response(response.json(), cve_id)
                    # 存入缓存，设置1天过期
                    self.cache.set(cache_key, result, expire=86400)
                    return result
                
                elif response.status_code == 403:
                    self.logger.error("NVD API密钥无效或已过期")
                    break
                
                elif response.status_code == 429:
                    self.logger.warning("达到API速率限制")
                    if 'nvd' in self.config and 'rate_limit' in self.config['nvd']:
                        time.sleep(30)
                    continue
                
                elif response.status_code == 503:
                    self.logger.warning("NVD API服务暂时不可用")
                    continue
                
                else:
                    self.logger.error(f"未预期的HTTP状态码: {response.status_code}")
                
            except requests.exceptions.SSLError as e:
                self.logger.error(f"SSL错误: {str(e)}")
                if attempt < max_retries - 1:
                    continue
                else:
                    break
                
            except requests.exceptions.Timeout:
                self.logger.warning(f"请求超时 (尝试 {attempt + 1}/{max_retries})")
                continue
            
            except requests.exceptions.ConnectionError as e:
                self.logger.error(f"连接错误: {str(e)}")
                if attempt < max_retries - 1:
                    continue
                else:
                    break
                
            except requests.RequestException as e:
                self.logger.error(f"请求异常: {str(e)}")
                if attempt < max_retries - 1:
                    continue
                else:
                    break
                
            finally:
                session.close()
        
        return self._get_empty_cve_details()

    def _get_empty_cve_details(self):
        """返回空的CVE详情"""
        return {
            'title': '获取失败',
            'description': '获取失败',
            'description_zh': '获取失败',
            'severity': '未知',
            'cvss_score': '未知',
            'affected_configs': '未知',
            'references': '未知',
            'published': '未知',
            'modified': '未知',
            'analysis': '获取失败'
        }

    def _parse_nvd_response(self, data, cve_id):
        """解析NVD API响应"""
        try:
            if not data.get('vulnerabilities'):
                return self._get_empty_cve_details()
            
            vuln = data['vulnerabilities'][0]['cve']
            
            # 获取描述
            descriptions = vuln.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '未知')
            
            # 翻译描述
            self.logger.info(f"正在翻译 {cve_id} 的描述...")
            description_zh = self.translate_text(description)
            
            # 获取CVSS信息
            metrics = vuln.get('metrics', {})
            cvss_v31 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
            cvss_v30 = metrics.get('cvssMetricV30', [{}])[0] if metrics.get('cvssMetricV30') else {}
            cvss = cvss_v31 or cvss_v30
            
            # 获取并翻译受影响配置
            configurations = []
            for node in vuln.get('configurations', []):
                for match in node.get('nodes', []):
                    for cpe_match in match.get('cpeMatch', []):
                        criteria = cpe_match.get('criteria', '')
                        if criteria:
                            parts = criteria.split(':')
                            if len(parts) > 4:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else '*'
                                config = f"{vendor}:{product}:{version}"
                                configurations.append(config)
            
            # 获取并翻译参考信息
            references = []
            for ref in vuln.get('references', []):
                ref_url = ref.get('url', '')
                ref_tags = ref.get('tags', [])
                if ref_url:
                    ref_info = f"链接: {ref_url}"
                    if ref_tags:
                        ref_info += f" (标签: {', '.join(ref_tags)})"
                    references.append(ref_info)
            
            # 翻译严重程度
            severity_map = {
                'CRITICAL': '严重',
                'HIGH': '高危',
                'MEDIUM': '中危',
                'LOW': '低危',
                'NONE': '无',
                'UNKNOWN': '未知'
            }
            
            severity = cvss.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            severity_zh = severity_map.get(severity, '未知')
            
            return {
                'title': description[:100] + '...' if len(description) > 100 else description,
                'description': description,
                'description_zh': description_zh,
                'severity': severity_zh,
                'cvss_score': cvss.get('cvssData', {}).get('baseScore', '未知'),
                'affected_configs': '; '.join(configurations) if configurations else '未知',
                'references': '; '.join(references) if references else '未知',
                'published': vuln.get('published', '未知'),
                'modified': vuln.get('lastModified', '未知')
            }
            
        except Exception as e:
            self.logger.error(f"解析NVD响应失败: {str(e)}")
            return self._get_empty_cve_details()

    def _get_severity(self, item):
        """获取CVE严重程度"""
        try:
            impact = item.get('impact', {})
            base_metric_v3 = impact.get('baseMetricV3', {})
            cvss_v3 = base_metric_v3.get('cvssV3', {})
            return cvss_v3.get('baseSeverity', '未知')
        except:
            return '未知'

    def scan(self):
        """扫描CVE信息"""
        checkpoint_file = 'scan_checkpoint.json'
        output_file = 'cve_simple_stats.csv'
        
        # 尝试恢复之前的扫描进度
        if os.path.exists(checkpoint_file):
            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                cve_map = json.load(f)
            self.logger.info(f"从检查点恢复了 {len(cve_map)} 条记录")
        else:
            cve_map = {}
        
        try:
            query = self.config['search']['query']
            limit = self.config['search'].get('limit', 1)
            self.logger.info(f"\n执行查询: {query} (限制 {limit} 页)")
            
            # 创建或追加CSV文件
            file_exists = os.path.exists(output_file)
            with open(output_file, 'a', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                
                # 如果文件不存在，写入表头
                if not file_exists:
                    writer.writerow([
                        '查询语句',
                        'CVE编号',
                        '影响资产数量',
                        '已验证',
                        '漏洞名称',
                        '描述(英文)',
                        '描述(中文)',
                        '严重程度',
                        'CVSS分数',
                        '受影响的软件配置',
                        '参考信息',
                        '发布日期',
                        '最后修改日期'
                    ])
                
                page = 1
                while page <= limit:
                    try:
                        self.logger.info(f"获取第 {page} 页数据...")
                        results = self.api.search(query, page=page)
                        
                        if page == 1:
                            self.logger.info(f"\n找到总计 {results['total']} 个结果")
                        
                        if not results['matches']:
                            break
                        
                        # 收集需要处理的CVE
                        cves_to_process = []
                        for result in results['matches']:
                            vulns = result.get('vulns', {})
                            for cve_id, vuln_info in vulns.items():
                                if cve_id not in cve_map or 'details' not in cve_map[cve_id]:
                                    cves_to_process.append((cve_id, vuln_info))
                        
                        # 使用线程池并发处理CVE
                        with concurrent.futures.ThreadPoolExecutor(
                            max_workers=self.config['nvd'].get('concurrent_requests', 5)
                        ) as executor:
                            # 批量处理CVE
                            batch_size = self.config['nvd'].get('batch_size', 10)
                            for i in range(0, len(cves_to_process), batch_size):
                                batch = cves_to_process[i:i + batch_size]
                                futures = []
                                
                                for cve_id, vuln_info in batch:
                                    future = executor.submit(self.get_cve_details, cve_id)
                                    futures.append((cve_id, vuln_info, future))
                                
                                # 处理完成的结果
                                for cve_id, vuln_info, future in futures:
                                    try:
                                        details = future.result()
                                        cve_map[cve_id] = {
                                            'count': 1,
                                            'verified': isinstance(vuln_info, dict) and vuln_info.get('verified', False),
                                            'details': details
                                        }
                                        
                                        # 实时写入该条记录
                                        writer.writerow([
                                            query,
                                            cve_id,
                                            cve_map[cve_id]['count'],
                                            'Yes' if cve_map[cve_id]['verified'] else 'No',
                                            details['title'],
                                            details['description'],
                                            details['description_zh'],
                                            details['severity'],
                                            details['cvss_score'],
                                            details['affected_configs'],
                                            details['references'],
                                            details['published'],
                                            details['modified']
                                        ])
                                        f.flush()
                                        
                                    except Exception as e:
                                        self.logger.error(f"处理 {cve_id} 失败: {e}")
                                
                                # 保存检查点
                                with open(checkpoint_file, 'w', encoding='utf-8') as cf:
                                    json.dump(cve_map, cf, ensure_ascii=False, indent=2)
                                
                                # 避免请求过快
                                time.sleep(1)
                        
                        self.logger.info(f"当前已处理 {len(cve_map)} 个CVE")
                        
                        if len(results['matches']) < 100:  # Shodan默认每页100条
                            break
                        
                        page += 1
                        
                    except shodan.APIError as e:
                        self.logger.error(f"API错误: {e}")
                        break
                    except Exception as e:
                        self.logger.error(f"处理页面 {page} 时发生错误: {e}")
                        continue
            
            # 输出统计信息
            verified_count = sum(1 for data in cve_map.values() if data['verified'])
            self.logger.info(f"\n扫描完成!")
            self.logger.info(f"扫描了 {page} 页数据")
            self.logger.info(f"共发现 {len(cve_map)} 个CVE")
            self.logger.info(f"其中已验证的CVE: {verified_count} 个")
            self.logger.info(f"未验证的CVE: {len(cve_map) - verified_count} 个")
            
        except Exception as e:
            self.logger.error(f"扫描过程发生错误: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            
        finally:
            # 扫描完成后删除检查点文件
            if os.path.exists(checkpoint_file):
                os.remove(checkpoint_file)

    def get_cves_batch(self, cve_ids):
        """批量获取CVE信息"""
        max_retries = 3
        base_delay = 2
        
        headers = {
            'User-Agent': 'CVE-Research-Tool/1.0',
            'Accept': 'application/json',
        }
        
        if 'nvd' in self.config and 'api_key' in self.config['nvd']:
            headers['apiKey'] = self.config['nvd']['api_key']
        
        session = requests.Session()
        retry_strategy = requests.adapters.Retry(
            total=max_retries,
            backoff_factor=base_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
            pool_block=False
        )
        session.mount("https://", adapter)
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            cve_list = ','.join(cve_ids)
            params = {
                'cveId': cve_list
            }
            
            timeout = (5, self.config['cve']['timeout'])
            
            response = session.get(
                url,
                params=params,
                headers=headers,
                timeout=timeout,
                verify=True
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"批量获取CVE失败: {response.status_code}")
                return None
            
        except Exception as e:
            self.logger.error(f"批量获取CVE异常: {str(e)}")
            return None
        finally:
            session.close()

if __name__ == "__main__":
    scanner = CVEStats()
    scanner.scan() 