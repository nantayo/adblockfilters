#!/usr/bin/env python3
"""adblockfilters 单文件流水线：一次运行 = 拿到一份新鲜的 mosdns 屏蔽列表。

流程：
  1. 从 README.md 的表格读取上游规则源配置（只读，不回写）
  2. 并发下载各源（单个源失败只跳过它，不让某一天的坏数据污染整个流程）
  3. 解析 host / dns 两种格式，合并成 {可注册域: {子域}}，另收集 @@|| 白名单
  4. 先按父域去重，再对保留域做 A/AAAA 活性检测（本机 smartdns，配置见
     smartdns.conf，sqlite 增量缓存 domain.db）。判死的保留域会补测其被
     吸收的子域：只要还有一个活子域，父域就要保留（mosdns 按后缀匹配，
     父域在列表里就能继续屏蔽这些子域）
  5. 剔除死域名、应用 @@ 白名单，产出 rules/adblockmosdns.txt

调试参数：
  -v            提高日志级别（INFO/DEBUG）
  --skip-check  跳过活性检测，只跑 解析→去重→产出 链路（不需要 smartdns）
"""
import argparse
import asyncio
import logging
import os
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Set, Tuple

import dns.asyncresolver
import dns.resolver
import httpx
import IPy
from tld import get_tld

# ---------------------------------------------------------------- 配置 ----

HOMEPAGE = "https://github.com/nantayo/adblockfilters"

# 存活检测走工作流里临时拉起的本地 smartdns（见 smartdns.conf）
NAMESERVERS = os.environ.get("ADBLOCK_NS", "127.0.0.1").split(",")
PORT = int(os.environ.get("ADBLOCK_PORT", "5053"))
RETEST_ALIVE = 14 * 24 * 3600      # 有解析记录的域名 14 天才复测一次
MAX_TASK = 200                     # 并发上限

# 单个源最多忍 60 秒，连接阶段 10 秒，避免某个上游挂住拖死整个任务
TIMEOUT = httpx.Timeout(10.0, read=60.0, write=30.0, pool=10.0)

# 产出缩水/暴涨超过这个幅度就中止，别让一天的坏数据覆盖掉仓库里的好数据
MIN_RATIO, MAX_RATIO = 0.7, 1.5

# 筛选 DNS 级别规则
INVALID_CHARS = set('/*$?#=:;|%^@,')

PWD = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(PWD, "rules")
OUT_FILE = os.path.join(RULES_DIR, "adblockmosdns.txt")
BLACK_FILE = os.path.join(RULES_DIR, "black.txt")
README_FILE = os.path.join(PWD, "README.md")
DB_FILE = os.path.join(PWD, "domain.db")

log = logging.getLogger("adblockfilters")


# ---------------------------------------------------------------- 工具 ----

def full_domain(fld: str, subdomain: str) -> str:
    """blockDict 以 (fld, subdomain) 两级存放，这里拼回完整域名"""
    return "%s.%s" % (subdomain, fld) if subdomain else fld


def is_pure_domain(s: str) -> bool:
    if not s or '.' not in s:
        return False
    if any(c in INVALID_CHARS for c in s):
        return False
    if s.startswith('-') or s.startswith('.') or s.endswith('.'):
        return False
    return True


def analysis(address: str) -> Tuple[str, str]:
    """域名/公网 IP -> (fld, subdomain)。IP 原样返回，fld=IP、子域为空"""
    address_tmp = address
    if address.rfind(":") > 0:
        address_tmp = address[:address.rfind(":")]
    try:
        res = get_tld(address_tmp, fix_protocol=True, as_object=True)
        return res.fld, res.subdomain
    except Exception:
        pass
    try:
        ip_address = IPy.IP(address_tmp)
        if ip_address.iptype() == "PUBLIC":
            return address, ""
    except Exception:
        pass
    raise Exception('"%s": not domain or public ip' % address)


# ------------------------------------------------- 规则源（README.md）-----

class Rule(object):
    def __init__(self, name: str, type: str, url: str):
        self.name = name
        self.filename = name.replace(' ', '_') + '.txt'
        self.type = type
        self.url = url


def read_rules(filename: str) -> List[Rule]:
    """README.md 的表格就是规则源配置表；只取前三列（名称/类型/链接），
    链接列之后的任何内容（如旧版的更新日期列）一律忽略"""
    rule_list: List[Rule] = []
    with open(filename, "r") as f:
        for line in f:
            line = line.replace('\r', '').replace('\n', '')
            if line.find('|') == 0 and line.rfind('|') == len(line) - 1:
                rule = list(map(lambda x: x.strip(), line[1:-1].split('|')))
                if (len(rule) >= 3
                        and rule[2].find('(') > 0 and rule[2].find(')') > 0
                        and rule[1].find('(') < 0):
                    url = rule[2][rule[2].find('(') + 1:rule[2].find(')')]
                    match_obj = re.match(
                        r'(http|https)://[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                    if match_obj:
                        rule_list.append(Rule(rule[0], rule[1], url))
    return rule_list


# ------------------------------------------------------------ 下载规则 ----

def download_rules(rule_list: List[Rule], path: str):
    """并发下载上游规则。单个源失败只跳过它（记 ERROR），不让某一天的
    坏数据污染整个流程。"""
    os.makedirs(path, exist_ok=True)

    async def _update():
        transport = httpx.AsyncHTTPTransport(retries=2)
        async with httpx.AsyncClient(timeout=TIMEOUT, transport=transport,
                                     follow_redirects=True) as client:
            await asyncio.gather(
                *[_download_one(rule, path, client) for rule in rule_list])

    asyncio.run(_update())


async def _download_one(rule: Rule, path: str, client: httpx.AsyncClient):
    file_name = os.path.join(path, rule.filename)
    file_download = file_name + '.download'
    try:
        if os.path.exists(file_download):
            os.remove(file_download)

        response = await client.get(rule.url)
        response.raise_for_status()
        # 只挡掉明显是错误页；GitHub 的 404 也是 text/plain，靠 raise_for_status
        content_type = response.headers.get("Content-Type", "")
        if "html" in content_type.lower():
            raise Exception("Content-Type[%s] error" % content_type)
        # 先落 .download 再改名，避免下载到一半的残file被当成有效源
        with open(file_download, 'wb') as f:
            f.write(response.content)
        os.replace(file_download, file_name)
        log.debug("%s: downloaded" % rule.name)
    except Exception as e:
        log.error('%s download failed: %s' % (rule.name, e))
        if os.path.exists(file_download):
            os.remove(file_download)


# ------------------------------------------------------------ 规则解析 ----

def parse_host_line(line: str) -> Optional[Tuple[str, str]]:
    """host 模式: 0.0.0.0 example.com / 127.0.0.1 example.com"""
    try:
        if re.match(r'^#.*', line):
            return None
        line = line.replace('\t', ' ')
        if line.find('#') > 0:
            line = line[:line.find('#')].strip()
        if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
            domain = line.split(' ')[-1]
            if domain in {'localhost', 'localhost.localdomain', 'local', '0.0.0.0'}:
                return None
            if not is_pure_domain(domain):
                return None
            return analysis(domain)
        raise Exception('"%s": not keep' % line)
    except Exception as e:
        # 上游文件里大量注释/说明行本来就不该保留，按 debug 记，别刷一屏 ERROR
        log.debug("%s" % e)
        return None


def parse_dns_line(line: str) -> Tuple[Optional[Tuple[str, str]], Optional[Tuple[str, str]]]:
    """dns 模式: ||domain^（屏蔽）/ @@||domain^（白名单）"""
    try:
        if line.startswith('!') or line.startswith('#') or re.match(r'^\[.*\]$', line):
            return None, None
        if line.find('#') > 0:
            line = line[:line.find('#')].strip()

        # @@||domain^：例外规则，域名不屏蔽
        m = re.match(r'^@@\|\|([^\^/]+)\^$', line)
        if m:
            d = m.group(1)
            if is_pure_domain(d):
                return None, analysis(d)
            return None, None

        # ||domain^
        m = re.match(r'^\|\|([^\^/]+)\^$', line)
        if m:
            d = m.group(1)
            if is_pure_domain(d):
                return analysis(d), None
            return None, None

        # 其它形式（含 / * $ ? 等）一律跳过
        raise Exception('"%s": not keep' % line)
    except Exception as e:
        log.debug("%s" % e)
        return None, None


def parse_rule(rule: Rule, path: str) -> Tuple[Dict[str, Set[str]], Set[str]]:
    """解析单个规则文件 -> ({fld: {子域}}, {白名单完整域名})"""
    block_dict: Dict[str, Set[str]] = {}
    unblock_set: Set[str] = set()
    filename = os.path.join(path, rule.filename)
    if not os.path.exists(filename):
        return block_dict, unblock_set
    with open(filename, "r", encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.replace('\r', '').replace('\n', '').strip()
            if not line:
                continue
            if rule.type == 'host':
                block = parse_host_line(line)
                if block:
                    block_dict.setdefault(block[0], set()).add(block[1])
            elif rule.type == 'dns':
                block, unblock = parse_dns_line(line)
                if block:
                    block_dict.setdefault(block[0], set()).add(block[1])
                if unblock:
                    unblock_set.add(full_domain(unblock[0], unblock[1]))
    log.info("%s: block fld=%d, unblock=%d" % (rule.name, len(block_dict), len(unblock_set)))
    return block_dict, unblock_set


def parse_rules(rule_list: List[Rule], path: str) -> Tuple[Dict[str, Set[str]], Set[str]]:
    """并发解析所有上游规则，合并成 {fld: {subdomain}} 和白名单集合"""
    workers = max(4, os.cpu_count() or 4)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(parse_rule, r, path) for r in rule_list if r.type in ('host', 'dns')]
        block_dict: Dict[str, Set[str]] = {}
        unblock_set: Set[str] = set()
        for future in as_completed(futures):
            block, unblock = future.result()
            for fld, subs in block.items():
                block_dict.setdefault(fld, set()).update(subs)
            unblock_set |= unblock
    return block_dict, unblock_set


# ---------------------------------------------------------------- 去重 ----

def repetition(subdomains: Iterable[str]) -> List[str]:
    """剔除"已被同组父域覆盖"的子域：逐级查父域是否在集合内，O(总标签数)"""
    s = set(subdomains)
    if '' in s:          # 顶级域自身即可覆盖整组
        return ['']
    kept = []
    for d in s:
        labels = d.split('.')
        for k in range(1, len(labels)):
            if '.'.join(labels[k:]) in s:
                break
        else:
            kept.append(d)
    kept.sort()
    return kept


def dedupe_plan(block_dict: Dict[str, Set[str]]) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """第一阶段去重（不依赖活性信息）。

    返回 (kept_by_fld, covered)：covered[保留域] = 被它吸收掉的完整子域列表。
    活性检测阶段只有 kept 需要检测；covered 仅用于"死父域补测子域"。
    """
    kept_by_fld: Dict[str, List[str]] = {}
    covered: Dict[str, List[str]] = {}
    for fld, subs in block_dict.items():
        kept = repetition(subs)
        kept_by_fld[fld] = kept
        kept_set = set(kept)
        for sub in subs:
            if sub in kept_set:
                continue
            child = full_domain(fld, sub)
            labels = sub.split('.')
            for k in range(1, len(labels)):
                parent = '.'.join(labels[k:])
                if parent in kept_set:
                    covered.setdefault(full_domain(fld, parent), []).append(child)
                    break
            else:
                # 没有保留祖先时，只有顶级域自身能覆盖整组
                if '' in kept_set:
                    covered.setdefault(fld, []).append(child)
    return kept_by_fld, covered


def finalize(kept_by_fld: Dict[str, List[str]], dead: Set[str],
             child_dead: Set[str], covered: Dict[str, List[str]]) -> List[str]:
    """第二阶段：按检测结果产出最终清单。

    判死的域名原则上剔除；但父域已死而下面还有活着的子域时，父域要保留，
    否则会漏掉还能用起来的子域名。
    """
    domain_list: List[str] = []
    for fld in sorted(kept_by_fld.keys()):
        for subdomain in kept_by_fld[fld]:
            domain = full_domain(fld, subdomain)
            if domain not in dead:
                domain_list.append(domain)
            elif any(c not in child_dead for c in covered.get(domain, ())):
                domain_list.append(domain)
    return domain_list


def apply_whitelist(block_list: List[str], unblock_set: Set[str]) -> List[str]:
    """应用 @@||domain^ 白名单：剔除例外域名本身及其所有子域"""
    if not unblock_set:
        return block_list
    suffixes = tuple("." + u for u in unblock_set)
    return [d for d in block_list
            if d not in unblock_set and not d.endswith(suffixes)]


# ------------------------------------------------------------ 活性检测 ----

class DomainDB(object):
    """域名库：domain -> 是否判死 / 上次检测时间 / 解析记录。

    存成 release asset，避免每天对四十多万个域名全量探测一遍公共 DNS。
    只保存"保留域"（去重后）的检测结果。
    """

    __deleted = False   # 没有删除过记录就不需要 VACUUM

    def __init__(self, db_file: str):
        self.__table = "T_DOMAIN"
        self.__conn = None
        try:
            self.__conn = sqlite3.connect(db_file, timeout=30)
            # 探一下库是否可用：上一次上传的 asset 可能是坏的
            self.__conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite3.DatabaseError as e:
            # 库坏了不要跟着挂，删掉重建即可（第二天探测会全量重来一次）
            log.error("domain database broken (%s), recreate" % e)
            self.__safe_close()
            for suffix in ("", "-wal", "-shm", "-journal"):
                try:
                    os.remove(db_file + suffix)
                except OSError:
                    pass
            self.__conn = sqlite3.connect(db_file, timeout=30)
        self.__init_db()

    def __safe_close(self):
        try:
            if self.__conn:
                self.__conn.close()
        except Exception:
            pass
        self.__conn = None

    def close(self):
        if self.__deleted:
            self.__execute('VACUUM')
        self.__safe_close()

    def __execute(self, sql: str):
        try:
            return self.__conn.execute(sql)
        except sqlite3.DatabaseError as e:
            log.exception(e)
            return None

    def __init_db(self):
        rows = self.__execute("SELECT name FROM sqlite_master WHERE type='table'")
        if rows and self.__table in [r[0] for r in rows]:
            return
        # 库刚探过是好的，这里直接用 connection 执行，出错就让它响亮地失败
        self.__conn.execute(
            'CREATE TABLE %s ('
            '  ID INTEGER PRIMARY KEY AUTOINCREMENT,'
            '  domain TEXT NOT NULL,'
            '  isBlock INTEGER NOT NULL CHECK (isBlock IN (0, 1)) DEFAULT 0,'
            '  timeStamp INTEGER NOT NULL,'
            '  ipList TEXT'
            ')' % self.__table)
        self.__conn.execute(
            'CREATE UNIQUE INDEX INDEX_%s_UNIQUE on %s (domain)'
            % (self.__table, self.__table))
        self.__conn.execute(
            'CREATE INDEX index_%s on %s (isBlock, timeStamp, domain)'
            % (self.__table, self.__table))
        self.__conn.commit()

    def get_all(self) -> List[Tuple]:
        rows = self.__execute(
            "SELECT domain, isBlock, timeStamp, ipList FROM %s" % self.__table)
        if not rows:
            return []
        return list(rows)

    def update_all(self, rows: List[Tuple], batch_size=500):
        sql = ("REPLACE INTO %s (domain, isBlock, timeStamp, ipList) "
               "VALUES (?, ?, ?, ?)" % self.__table)
        try:
            for i in range(0, len(rows), batch_size):
                self.__conn.executemany(sql, rows[i:i + batch_size])
            self.__conn.commit()
        except sqlite3.DatabaseError as e:
            log.exception(e)

    def delete_batch(self, domains: List[str], batch_size=500):
        self.__deleted = True
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            placeholders = ','.join(['?'] * len(batch))
            self.__conn.execute(
                "DELETE FROM %s WHERE domain IN (%s)" % (self.__table, placeholders),
                batch)
        self.__conn.commit()


class DomainState(object):
    """单个域名的检测状态（内存对象，变化后才落库）"""
    __slots__ = ("domain", "is_block", "ts", "ip_list", "dirty")

    def __init__(self, domain: str, is_block: int = None, ts: int = None, ip_list: str = None):
        self.domain = domain
        if ts is None:
            self.is_block, self.ts, self.ip_list, self.dirty = False, int(time.time()), [], True
        else:
            self.is_block, self.ts, self.dirty = bool(is_block), ts, False
            self.ip_list = ip_list.split(',') if ip_list else []

    def set_ips(self, ip_list: List[str]):
        self.ip_list = list(ip_list)
        self.is_block = not self.ip_list
        self.ts = int(time.time())
        self.dirty = True

    def to_tuple(self) -> Tuple:
        return (self.domain, int(self.is_block), self.ts,
                ','.join(map(str, self.ip_list)) if self.ip_list else None)


async def _resolve(resolver, domain: str) -> List[str]:
    """A/AAAA 都拿不到记录（或只有 0.0.0.0/::）就算死"""
    ip_list: List[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(qname=domain, rdtype=rdtype)
            ip_list.extend(
                ip for ip in (str(item) for item in answer)
                if ip not in ("0.0.0.0", "::"))
        except dns.resolver.NoAnswer:
            log.debug('"%s" (%s): no answer' % (domain, rdtype))
        except dns.resolver.NXDOMAIN:
            log.debug('"%s" (%s): nxdomain' % (domain, rdtype))
        except Exception as e:
            log.debug('"%s" (%s): %s' % (domain, rdtype, e))
    return ip_list


async def _resolve_all(domains: List[str]) -> Dict[str, List[str]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = NAMESERVERS
    resolver.port = PORT
    resolver.lifetime = 10
    resolver.timeout = 5
    semaphore = asyncio.Semaphore(MAX_TASK)

    async def _one(domain: str):
        async with semaphore:
            return domain, await _resolve(resolver, domain)

    pairs = await asyncio.gather(*[_one(d) for d in domains])
    return dict(pairs)


def probe_only(domains: Iterable[str]) -> Set[str]:
    """不落库的探测（用于死父域的被吸收子域），返回已死集合"""
    domains = list(domains)
    if not domains:
        return set()
    log.debug("probe without db: %d" % len(domains))
    results = asyncio.run(_resolve_all(domains))
    return {d for d, ips in results.items() if not ips}


def check_liveness(domains: Iterable[str], db_file: str) -> Set[str]:
    """对保留域做存活检测，返回已死的集合。

    判死口径：A 和 AAAA 都拿不到记录就算死，包含 NXDOMAIN、NOERROR-NODATA，
    以及 SERVFAIL / 超时等查不动的情况（GitHub 出口 IP 被公共 DNS 限流时
    会批量出现，此时域名事实上也联不通，判死是符合预期的）。
    代价是限流期间会误剔一部分域名，但判死的域名下次运行就会复测，只影响一天。
    """
    states: Dict[str, DomainState] = {d: DomainState(d) for d in domains}
    db = DomainDB(db_file)
    try:
        # 合并上次的结果：拿到旧状态，并找出已经从上游消失的域名
        stale: List[str] = []
        for row in db.get_all():
            if row[0] in states:
                states[row[0]] = DomainState(row[0], row[1], row[2], row[3])
            else:
                stale.append(row[0])
        log.debug("domain dict: %d, stale: %d" % (len(states), len(stale)))

        # 判死的(无记录)每次复测；有记录的按 RETEST_ALIVE 复测
        now = int(time.time())
        need = [s for s in states.values()
                if not s.ip_list or now - s.ts > RETEST_ALIVE]
        if need:
            log.info("resolve domains: %d" % len(need))
            results = asyncio.run(_resolve_all([s.domain for s in need]))
            for s in need:
                s.set_ips(results[s.domain])

        dead = {d for d, s in states.items() if s.is_block}
        log.info("dead domains: %d / %d" % (len(dead), len(states)))

        changed = [s.to_tuple() for s in states.values() if s.dirty]
        if changed:
            db.update_all(changed)
        if stale:
            db.delete_batch(stale)
        return dead
    finally:
        db.close()


# ---------------------------------------------------------------- 产出 ----

def check_count(count: int):
    """和上次产出的域名数比较，缩水/暴涨超过阈值就中止"""
    old = 0
    try:
        with open(OUT_FILE) as f:
            for line in f:
                if "domains=" in line:
                    old = int(line.split("domains=")[1].split()[0])
                    break
    except (OSError, ValueError, IndexError):
        return
    if old and not MIN_RATIO * old <= count <= MAX_RATIO * old:
        raise SystemExit("refuse to write: %d domains, last run had %d" % (count, old))


def generate(block_list: List[str]):
    """mosdns 屏蔽列表：一行一个域名，产物只留一行文件头"""
    log.info("generate adblock MosDNS: %d domains" % len(block_list))
    with open(OUT_FILE, 'w', encoding='utf-8', newline='\n') as f:
        f.write("# AdBlock MosDNS | %s | domains=%d | %s\n"
                % (time.strftime("%Y/%m/%d %H:%M:%S", time.localtime()),
                   len(block_list), HOMEPAGE))
        for domain in block_list:
            f.write("%s\n" % domain)


def dump_dead(dead: Set[str]):
    """死域名清单，仅用于人工排查；过滤逻辑用的是内存里的集合"""
    with open(BLACK_FILE, 'w', encoding='utf-8') as f:
        for domain in sorted(dead):
            f.write("%s\n" % domain)
    log.info("black list: %d" % len(dead))


# ---------------------------------------------------------------- 主流程 ----

def refresh(skip_check: bool = False):
    rule_list = read_rules(README_FILE)

    # 1. 下载上游规则（单个源失败只跳过它）
    download_rules(rule_list, RULES_DIR)

    # 2. 解析成 {fld: {subdomain}} + 白名单
    block_dict, unblock_set = parse_rules(rule_list, RULES_DIR)
    log.info("parsed: fld=%d, domains=%d, unblock=%d"
             % (len(block_dict), sum(len(s) for s in block_dict.values()), len(unblock_set)))

    # 3. 先按父域去重，再对保留域做活性检测
    kept_by_fld, covered = dedupe_plan(block_dict)
    kept_all = [full_domain(f, s) for f, subs in kept_by_fld.items() for s in subs]
    log.info("deduped: keep %d domains" % len(kept_all))

    if skip_check:
        log.warning("--skip-check: 跳过活性检测")
        dead: Set[str] = set()
        child_dead: Set[str] = set()
    else:
        dead = check_liveness(kept_all, DB_FILE)
        # 死掉的保留域：补测它的被吸收子域，只要还有一个活着父域就要保留
        extra = sorted({c for d in dead for c in covered.get(d, ())})
        child_dead = probe_only(extra)

    # 4. 剔除死域名、应用 @@ 白名单
    block_list = finalize(kept_by_fld, dead, child_dead, covered)
    before_whitelist = len(block_list)
    block_list = apply_whitelist(block_list, unblock_set)
    if unblock_set:
        log.info("whitelist removed: %d" % (before_whitelist - len(block_list)))

    # 5. 产出；black.txt 仅作排查用，不进 git
    check_count(len(block_list))
    generate(block_list)
    dump_dead(dead)


def main():
    parser = argparse.ArgumentParser(description="adblockfilters 单文件流水线")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="提高日志级别（-v INFO, -vv DEBUG）")
    parser.add_argument("--skip-check", action="store_true",
                        help="跳过活性检测（不需要 smartdns），只跑解析/去重/产出")
    args = parser.parse_args()

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(message)s", stream=sys.stderr)

    refresh(skip_check=args.skip_check)


if __name__ == '__main__':
    main()
