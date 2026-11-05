"""规则源统计分析（手工/按月运行，与每日出成品无关）。

逐个上游统计：可解析比例、独有贡献、中文覆盖，用于评估要不要增删规则源。
上游原始规则现拉一份到临时目录，不进 git。

依赖 update.py 的下载/行解析函数，避免维护两份解析逻辑。
"""
import os
import shutil
import tempfile
from collections import Counter, defaultdict

import update as U

EXCLUDE_FILES = {'adblockmosdns.txt', 'domain.txt', 'black.txt'}

CN_TLDS = {'cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn'}

CN_BRANDS = (
    'baidu', 'bdstatic', 'bdimg', 'hao123', 'iqiyi',
    'tencent', 'gtimg', 'qpic', 'qlogo', 'tenpay', 'foxmail',
    'weixin', 'wechat',
    'alibaba', 'taobao', 'tmall', 'alipay', 'aliyun',
    'alicdn', 'alimama', 'alipayobjects',
    'qcloud', 'myqcloud',
    'bytedance', 'toutiao', 'douyin', 'pstatp', 'snssdk',
    'byteimg', 'ixigua', 'feishu',
    'xiaomi', 'miui', 'mijia', 'hpplay',
    'huawei', 'huaweicloud', 'hicloud', 'hicdn',
    'jingdong', 'meituan', 'dianping', 'pinduoduo',
    'suning', 'dangdang',
    'xiaojukeji', 'didiglobal',
    'ctrip', 'qunar', 'tuniu',
    'amap', 'gaode', 'autonavi',
    'bilibili', 'hdslb', 'youku', 'letv', 'pptv', 'mgtv', 'wasu',
    'kuaishou', 'gifshow',
    'zhihu', 'douban', 'tieba',
    'netease', 'sinaimg', 'weibo', 'sinaedge',
    'ifeng', 'phoenix', 'sohu',
    'kugou', 'kuwo', 'xiami', 'ximalaya',
    'qihoo', 'kingsoft', 'sogou',
    'unionpay', 'umeng',
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


def analyze(rule_list, rules_dir):
    """逐个上游统计：可解析比例、独有贡献、中文覆盖"""
    parser_map = {'host': U.parse_host_line, 'dns': U.parse_dns_line}

    stats = []
    domain_to_sources = defaultdict(set)

    for rule in rule_list:
        if rule.filename in EXCLUDE_FILES:
            continue
        parser = parser_map.get(rule.type)
        filepath = os.path.join(rules_dir, rule.filename)
        if not parser or not os.path.exists(filepath):
            stats.append({'name': rule.name, 'type': rule.type, 'file': rule.filename,
                          'url': rule.url, 'exists': False})
            continue

        valid = blank = comment = 0
        block_domains, unblock_domains = set(), set()

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
                block = unblock = None
                if rule.type == 'host':
                    block = parser(stripped)
                else:
                    block, unblock = parser(stripped)
                if block:
                    block_domains.add(U.full_domain(block[0], block[1]))
                if unblock:
                    unblock_domains.add(U.full_domain(unblock[0], unblock[1]))

        for d in block_domains | unblock_domains:
            domain_to_sources[d].add(rule.name)

        all_domains = block_domains | unblock_domains
        tld_counter = Counter(extract_tld_hint(d) for d in all_domains)
        cn_domains = {d for d in all_domains if is_cn_domain(d)}
        stats.append({
            'name': rule.name, 'type': rule.type, 'file': rule.filename,
            'url': rule.url, 'exists': True, 'valid': valid,
            'block_unique': len(block_domains), 'unblock_unique': len(unblock_domains),
            'all_domains': all_domains, 'block_domains': block_domains,
            'unblock_domains': unblock_domains,
            'top_tlds': tld_counter.most_common(5),
            'sample_domains': sorted(all_domains)[:8],
            'cn_domains': cn_domains,
            'cn_ratio': len(cn_domains) / len(all_domains) if all_domains else 0.0,
            'cn_samples': sorted(cn_domains)[:15],
        })

    print("loaded %d rules from README.md" % len(rule_list))
    print("=" * 130)
    print("per-source statistics")
    print("=" * 130)
    print("%-32s %-6s %10s %10s %10s" % ("source", "type", "block", "unblock", "total"))
    print("-" * 130)
    for s in sorted(stats, key=lambda x: -(x.get('block_unique', 0) + x.get('unblock_unique', 0))):
        if not s.get('exists'):
            print("%-32s %-6s   (download failed)" % (s['name'], s['type']))
            continue
        print("%-32s %-6s %10d %10d %10d" % (
            s['name'], s['type'], s['block_unique'], s['unblock_unique'],
            s['block_unique'] + s['unblock_unique']))
        print("    Top TLD : %s" % ', '.join(
            "%s(%d)" % (tld, cnt) for tld, cnt in s['top_tlds']))
        print("    样本    : %s" % ', '.join(s['sample_domains']))

    print()
    print("=" * 130)
    print("marginal contribution (domains ONLY this source has)")
    print("=" * 130)
    rows = []
    for s in stats:
        if not s.get('exists'):
            continue
        ex = sum(1 for d in s['all_domains'] if len(domain_to_sources[d]) == 1)
        own = len(s['all_domains'])
        rows.append((s['name'], ex, own, ex / own if own else 0.0))
    for name, ex, own, share in sorted(rows, key=lambda x: -x[1]):
        print("%-32s %14d / %-8d %13.1f%%" % (name, ex, own, share * 100))

    print()
    print("=" * 130)
    print("Chinese coverage")
    print("=" * 130)
    for s in sorted(stats, key=lambda x: -x.get('cn_ratio', 0)):
        if not s.get('exists'):
            continue
        print("\n### %s  [%s]" % (s['name'], s['type']))
        print("    区域判断   : %s" % region_hint(s['cn_ratio']))
        print("    中文域名数 : %d / %d  (%.2f%%)" % (
            len(s['cn_domains']), s['all_domains'], s['cn_ratio'] * 100))
        if s['cn_samples']:
            print("    中文样本   : %s" % ', '.join(s['cn_samples']))


def main():
    cwd = os.path.dirname(os.path.abspath(__file__))
    rule_list = [r for r in U.read_rules(os.path.join(cwd, 'README.md'))
                 if r.filename not in EXCLUDE_FILES]

    tmpdir = tempfile.mkdtemp(prefix='adblockfilters-src-')
    try:
        U.download_rules(rule_list, tmpdir)
        analyze(rule_list, tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    main()
