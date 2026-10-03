import os
import time
from collections import defaultdict, Counter

from loguru import logger
logger.remove()

from readme import ReadMe
from resolver import Resolver


EXCLUDE_FILES = {'adblockmosdns.txt', 'domain.txt', 'black.txt'}


# ===== 中文域名识别 =====

# 强信号：.cn 系列 TLD
CN_TLDS = {'cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn'}

# 弱信号：知名中文品牌关键词（长度 >= 4，避免误匹配）
CN_BRANDS = (
    # 百度系
    'baidu', 'bdstatic', 'bdimg', 'hao123', 'iqiyi',
    # 腾讯系
    'tencent', 'gtimg', 'qpic', 'qlogo', 'tenpay', 'foxmail',
    'weixin', 'wechat',
    # 阿里系
    'alibaba', 'taobao', 'tmall', 'alipay', 'aliyun',
    'alicdn', 'alimama', 'alipayobjects',
    'qcloud', 'myqcloud',
    # 字节系
    'bytedance', 'toutiao', 'douyin', 'pstatp', 'snssdk',
    'byteimg', 'ixigua', 'feishu',
    # 小米系
    'xiaomi', 'miui', 'mijia', 'hpplay',
    # 华为系
    'huawei', 'huaweicloud', 'hicloud', 'hicdn',
    # 电商
    'jingdong', 'meituan', 'dianping', 'pinduoduo',
    'suning', 'dangdang',
    # 出行
    'xiaojukeji', 'didiglobal',
    'ctrip', 'qunar', 'tuniu',
    'amap', 'gaode', 'autonavi',
    # 视频
    'bilibili', 'hdslb', 'youku', 'letv', 'pptv', 'mgtv', 'wasu',
    'kuaishou', 'gifshow',
    # 社区
    'zhihu', 'douban', 'tieba',
    # 门户
    'netease', 'sinaimg', 'weibo', 'sinaedge',
    'ifeng', 'phoenix', 'sohu',
    # 音乐
    'kugou', 'kuwo', 'xiami', 'ximalaya',
    # 搜索 / 安全
    'qihoo', 'kingsoft', 'sogou',
    # 支付
    'unionpay', 'umeng',
    # 其他
    'ucweb', 'eleme',
    'gdtimg',
)


def is_cn_domain(domain: str) -> bool:
    lower = domain.lower()
    parts = lower.split('.')
    if len(parts) >= 2:
        if parts[-1] == 'cn':
            return True
        if '.'.join(parts[-2:]) in CN_TLDS:
            return True
    for kw in CN_BRANDS:
        if kw in lower:
            return True
    return False


def full_domain(fld, subdomain):
    return "%s.%s" % (subdomain, fld) if subdomain else fld


def extract_tld_hint(domain):
    parts = domain.split('.')
    if len(parts) < 2:
        return domain
    if (len(parts) >= 3
            and parts[-2] in ('com', 'co', 'org', 'net', 'gov', 'edu', 'ac')
            and len(parts[-1]) == 2):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def region_hint(cn_ratio):
    if cn_ratio > 0.20:
        return "中文为主 (%.1f%% 中文域)" % (cn_ratio * 100)
    if cn_ratio > 0.05:
        return "中英混合 (%.1f%% 中文域)" % (cn_ratio * 100)
    return "国际为主 (%.1f%% 中文域)" % (cn_ratio * 100)


def analyze():
    cwd = os.getcwd()
    rules_dir = os.path.join(cwd, 'rules')

    readme = ReadMe(os.path.join(cwd, 'README.md'))
    ruleList = [r for r in readme.getRules() if r.filename not in EXCLUDE_FILES]
    print("loaded %d rules from README.md" % len(ruleList))

    resolver = Resolver(rules_dir)
    parser_map = {
        'host': resolver._Resolver__resolveHost,
        'dns':  resolver._Resolver__resolveDNS,
    }

    stats = []
    domain_to_sources = defaultdict(set)

    for rule in ruleList:
        parser = parser_map.get(rule.type)
        filepath = os.path.join(rules_dir, rule.filename)
        if not parser or not os.path.exists(filepath):
            stats.append({
                'name': rule.name, 'type': rule.type, 'file': rule.filename,
                'url': rule.url, 'exists': False,
            })
            continue

        t0 = time.time()
        valid = blank = comment = 0
        block_hits = unblock_hits = skip = 0
        block_domains = set()
        unblock_domains = set()

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    blank += 1
                    continue
                if stripped.startswith(('!', '#', '[')):
                    comment += 1
                    continue
                valid += 1
                block, unblock = parser(stripped)
                if block:
                    block_hits += 1
                    block_domains.add(full_domain(block[0], block[1]))
                elif unblock:
                    unblock_hits += 1
                    unblock_domains.add(full_domain(unblock[0], unblock[1]))
                else:
                    skip += 1

        cost = time.time() - t0
        for d in block_domains:
            domain_to_sources[d].add(rule.name)
        for d in unblock_domains:
            domain_to_sources[d].add(rule.name)

        all_domains = block_domains | unblock_domains
        tld_counter = Counter(extract_tld_hint(d) for d in all_domains)
        top_tlds = tld_counter.most_common(5)
        sample_domains = sorted(all_domains)[:8]

        cn_domains = {d for d in all_domains if is_cn_domain(d)}
        cn_ratio = len(cn_domains) / len(all_domains) if all_domains else 0.0
        cn_samples = sorted(cn_domains)[:15]

        stats.append({
            'name': rule.name, 'type': rule.type, 'file': rule.filename,
            'url': rule.url, 'exists': True,
            'valid': valid, 'blank': blank, 'comment': comment,
            'block_hits': block_hits, 'unblock_hits': unblock_hits,
            'skip': skip,
            'block_unique': len(block_domains),
            'unblock_unique': len(unblock_domains),
            'all_domains': all_domains,
            'block_domains': block_domains,
            'unblock_domains': unblock_domains,
            'top_tlds': top_tlds,
            'sample_domains': sample_domains,
            'cn_domains': cn_domains,
            'cn_ratio': cn_ratio,
            'cn_samples': cn_samples,
            'cost': cost,
        })

    # ---- TABLE 1 ----
    print()
    print("=" * 130)
    print("TABLE 1: per-source statistics")
    print("=" * 130)
    print("%-32s %-6s %9s %9s %9s %9s %10s %8s" % (
        "source", "type", "valid", "block", "unblock", "skip", "uniq", "sec"))
    print("-" * 130)
    for s in sorted(stats, key=lambda x: -(x.get('block_unique', 0) + x.get('unblock_unique', 0))):
        if not s.get('exists'):
            print("%-32s %-6s   (file missing)" % (s['name'], s['type']))
            continue
        print("%-32s %-6s %9d %9d %9d %9d %10d %8.2f" % (
            s['name'], s['type'], s['valid'],
            s['block_hits'], s['unblock_hits'], s['skip'],
            s['block_unique'] + s['unblock_unique'], s['cost']))

    # ---- TABLE 2 ----
    print()
    print("=" * 130)
    print("TABLE 2: marginal contribution (domains ONLY this source has)")
    print("=" * 130)
    print("%-32s %14s %14s %14s" % (
        "source", "exclusive_blk", "exclusive_unb", "share_of_own"))
    print("-" * 130)
    rows = []
    for s in stats:
        if not s.get('exists'):
            continue
        ex_blk = sum(1 for d in s['block_domains'] if len(domain_to_sources[d]) == 1)
        ex_unb = sum(1 for d in s['unblock_domains'] if len(domain_to_sources[d]) == 1)
        own = len(s['block_domains']) + len(s['unblock_domains'])
        share = (ex_blk + ex_unb) / own if own else 0.0
        rows.append((s['name'], ex_blk, ex_unb, own, share))
    for name, ex_blk, ex_unb, own, share in sorted(rows, key=lambda x: -(x[1] + x[2])):
        print("%-32s %14d %14d %13.1f%%" % (name, ex_blk, ex_unb, share * 100))

    # ---- TABLE 3: 每源中文分析 ----
    print()
    print("=" * 130)
    print("TABLE 3: per-source Chinese coverage")
    print("=" * 130)
    for s in sorted(stats, key=lambda x: -x.get('cn_ratio', 0)):
        if not s.get('exists'):
            continue
        print()
        print("### %s  [%s]" % (s['name'], s['type']))
        print("    区域判断   : %s" % region_hint(s['cn_ratio']))
        print("    中文域名数 : %d / %d  (%.2f%%)" % (
            len(s['cn_domains']), len(s['all_domains']), s['cn_ratio'] * 100))
        print("    Top TLD   : %s" % ', '.join(
            "%s(%d)" % (tld, cnt) for tld, cnt in s['top_tlds']))
        if s['cn_samples']:
            print("    中文样本   : %s" % ', '.join(s['cn_samples']))

    # ---- TABLE 4: 中文域名全局覆盖 ----
    print()
    print("=" * 130)
    print("TABLE 4: Chinese domains global coverage")
    print("=" * 130)
    all_cn = {d for d in domain_to_sources if is_cn_domain(d)}
    print("total Chinese domains across all sources: %d" % len(all_cn))

    cn_by_source = Counter()
    for d in all_cn:
        for src in domain_to_sources[d]:
            cn_by_source[src] += 1
    print()
    print("%-32s %14s" % ("source", "cn_domains_owned"))
    print("-" * 60)
    for name, cnt in cn_by_source.most_common():
        print("%-32s %14d" % (name, cnt))

    cn_exclusive = [d for d in all_cn if len(domain_to_sources[d]) == 1]
    print()
    print("Chinese domains owned by exactly one source: %d" % len(cn_exclusive))
    if cn_exclusive:
        print("sample (first 40):")
        for d in sorted(cn_exclusive)[:40]:
            src = next(iter(domain_to_sources[d]))
            print("    %-60s <- %s" % (d, src))


if __name__ == '__main__':
    analyze()