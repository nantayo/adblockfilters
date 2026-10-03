import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple

from loguru import logger

from app import MosDNS
from readme import Rule
from resolver import Resolver


class Filter(object):
    def __init__(self, ruleList: List[Rule], path: str):
        self.ruleList = ruleList
        self.path = path

    def __getFilters(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        def dictadd(d1, d2):
            d3 = {}
            for item in set(d1) | set(d2):
                d3[item] = d1.get(item, set()) | d2.get(item, set())
            return d3

        thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
        resolver = Resolver(self.path)

        parsers = {'host': resolver.resolveHost, 'dns': resolver.resolveDNS}
        taskList = []
        for rule in self.ruleList:
            logger.info("resolve %s..." % rule.name)
            parser = parsers.get(rule.type)
            if parser:
                taskList.append(thread_pool.submit(parser, rule))

        blockDict: Dict[str, Set[str]] = {}
        unblockDict: Dict[str, Set[str]] = {}
        for future in as_completed(taskList):
            b, u = future.result()
            blockDict = dictadd(blockDict, b)
            unblockDict = dictadd(unblockDict, u)

        return blockDict, unblockDict

    def __getBlackList(self, fileName: str) -> Set[str]:
        logger.info("resolve black list...")
        blackSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r', encoding='utf-8', errors='replace') as f:
                blackSet = {x.replace("\n", "") for x in f.readlines()}
        logger.info("black list: %d" % len(blackSet))
        return blackSet

    def __domainSort(self, domainDict: Dict[str, Set[str]], blackSet: Set[str]):
        def repetition(l):
            l = sorted(l, key=len)
            if len(l) < 2:
                return l
            if l[0] == '':
                return l[:1]
            tmp = set()
            for i in range(len(l) - 1):
                for j in range(i + 1, len(l)):
                    if re.match(r'.*\.%s$' % l[i], l[j]):
                        tmp.add(l[j])
            l = list(set(l) - tmp)
            l.sort()
            return l

        def get_domain(fld, subdomain):
            return "%s.%s" % (subdomain, fld) if subdomain else fld

        domainList = []
        domainSet_all = set()
        for fld in sorted(domainDict.keys()):
            subdomainList_origin = list(domainDict[fld])
            subdomainList = repetition(subdomainList_origin)

            for subdomain in subdomainList:
                subdomain_not_black = False
                for _subdomain in set(subdomainList_origin) - set(subdomainList):
                    if subdomain and not re.match(r'.*\.%s$' % subdomain, _subdomain):
                        continue
                    if get_domain(fld, _subdomain) not in blackSet:
                        subdomain_not_black = True
                        break

                domain = get_domain(fld, subdomain)
                if domain not in blackSet or subdomain_not_black:
                    domainList.append(domain)

            for subdomain in subdomainList_origin:
                domainSet_all.add(get_domain(fld, subdomain))

        return domainList, domainSet_all

    def __generateDomainBackup(self, domainSet, fileName: str):
        logger.info("generate domain backup...")
        if os.path.exists(fileName):
            os.remove(fileName)
        domainList = sorted(domainSet)
        with open(fileName, 'a', encoding='utf-8') as f:
            for domain in domainList:
                f.write("%s\n" % domain)
        logger.info("domain backup: %d" % len(domainList))

    def generate(self, sourceRule):
        blockDict, unblockDict = self.__getFilters()
        blackSet = self.__getBlackList(os.path.join(self.path, "black.txt"))

        blockList, blockSet_block = self.__domainSort(blockDict, blackSet)
        unblockList, unblockSet_unblock = self.__domainSort(unblockDict, blackSet)

        MosDNS(blockList, unblockList,
               os.path.join(self.path, "adblockmosdns.txt"), sourceRule).generateAll()

        # 供 blacklist.py 做连通性检测
        self.__generateDomainBackup(blockSet_block | unblockSet_unblock,
                                    os.path.join(self.path, "domain.txt"))
