import os
import re
from typing import Dict, Set, Tuple

from tld import get_tld
import IPy
from loguru import logger

from readme import Rule

# 筛选 DNS 级别规则
_INVALID_CHARS = set('/*$?#=:;|%^@,')

class Resolver(object):
    def __init__(self, path: str):
        self.path = path

    @staticmethod
    def __is_pure_domain(s: str) -> bool:
        if not s or '.' not in s:
            return False
        if any(c in _INVALID_CHARS for c in s):
            return False
        if s.startswith('-') or s.startswith('.') or s.endswith('.'):
            return False
        return True

    def __analysis(self, address: str) -> Tuple[str, str]:
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

    # host 模式: 0.0.0.0 example.com / 127.0.0.1 example.com
    def __resolveHost(self, line):
        try:
            if re.match(r'^#.*', line):
                return None, None
            line = line.replace('\t', ' ')
            if line.find('#') > 0:
                line = line[:line.find('#')].strip()
            if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                domain = line.split(' ')[-1]
                if domain in {'localhost', 'localhost.localdomain', 'local', '0.0.0.0'}:
                    return None, None
                if not self.__is_pure_domain(domain):
                    return None, None
                return self.__analysis(domain), None
            raise Exception('"%s": not keep' % line)
        except Exception as e:
            logger.error("%s" % e)
            return None, None

    # dns 模式: ||domain^ / @@||domain^
    def __resolveDNS(self, line):
        try:
            if line.startswith('!') or line.startswith('#') or re.match(r'^\[.*\]$', line):
                return None, None
            if line.find('#') > 0:
                line = line[:line.find('#')].strip()

            # @@||domain^
            m = re.match(r'^@@\|\|([^\^/]+)\^$', line)
            if m:
                d = m.group(1)
                if self.__is_pure_domain(d):
                    return None, self.__analysis(d)
                return None, None

            # ||domain^
            m = re.match(r'^\|\|([^\^/]+)\^$', line)
            if m:
                d = m.group(1)
                if self.__is_pure_domain(d):
                    return self.__analysis(d), None
                return None, None

            # 其它形式（含 / * $ ? 等）一律跳过
            raise Exception('"%s": not keep' % line)
        except Exception as e:
            logger.error("%s" % e)
            return None, None

    def _run(self, rule: Rule, parser):
        blockDict: Dict[str, Set[str]] = {}
        unblockDict: Dict[str, Set[str]] = {}
        filename = os.path.join(self.path, rule.filename)
        if not os.path.exists(filename):
            return blockDict, unblockDict
        with open(filename, "r", encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '').strip()
                if not line:
                    continue
                block, unblock = parser(line)
                if block:
                    blockDict.setdefault(block[0], set()).add(block[1])
                if unblock:
                    unblockDict.setdefault(unblock[0], set()).add(unblock[1])
        logger.info("%s: block=%d, unblock=%d" % (rule.name, len(blockDict), len(unblockDict)))
        return blockDict, unblockDict

    def resolveHost(self, rule: Rule):
        return self._run(rule, self.__resolveHost)

    def resolveDNS(self, rule: Rule):
        return self._run(rule, self.__resolveDNS)
