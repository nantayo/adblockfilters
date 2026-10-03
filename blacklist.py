import os
import time
import asyncio
import sqlite3
from typing import Dict, List, Tuple

from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType


class DomainDatabase(object):
    def __init__(self, dbFile: str):
        self.__table_domain = "T_DOMAIN"
        self.__conn = sqlite3.connect(dbFile)
        self.__execute('PRAGMA synchronous = OFF')
        self.__init_db()

    def close(self):
        self.__execute('VACUUM')
        self.__conn.close()

    def __execute(self, sql: str):
        try:
            return self.__conn.execute(sql)
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)

    def __checkTableExists(self, tableName: str) -> bool:
        try:
            sql = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            tableList = [row[0] for row in self.__execute(sql)]
            return tableName in tableList
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)
            return False

    def __updateData(self, sql: str, dataListTuple: list = None):
        c = None
        try:
            c = self.__conn.cursor()
            if dataListTuple:
                c.executemany(sql, dataListTuple)
            else:
                c.execute(sql)
            self.__conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)
        finally:
            if c:
                c.close()

    def __init_db(self):
        if not self.__checkTableExists(self.__table_domain):
            self.__execute(
                'CREATE TABLE %s ('
                '  ID INTEGER PRIMARY KEY AUTOINCREMENT,'
                '  domain TEXT NOT NULL,'
                '  isBlock INTEGER NOT NULL CHECK (isBlock IN (0, 1)) DEFAULT 0,'
                '  timeStamp INTEGER NOT NULL,'
                '  ipList TEXT'
                ')' % self.__table_domain
            )
            self.__execute(
                'CREATE UNIQUE INDEX INDEX_%s_UNIQUE on %s (domain)'
                % (self.__table_domain, self.__table_domain)
            )
            self.__execute(
                'CREATE INDEX index_%s on %s (isBlock, timeStamp, domain)'
                % (self.__table_domain, self.__table_domain)
            )

    def getAll(self) -> List[Tuple]:
        sql = "SELECT domain, isBlock, timeStamp, ipList FROM %s" % self.__table_domain
        return self.__execute(sql)

    def updateALL(self, domainList: List[Tuple]):
        sql = ("REPLACE INTO %s (domain, isBlock, timeStamp, ipList) "
               "VALUES (?, ?, ?, ?)" % self.__table_domain)
        self.__updateData(sql, domainList)

    def deleteBatch(self, domainList, batch_size=500):
        total_deleted = 0
        if len(domainList) < 1:
            return total_deleted

        self.__conn.execute("BEGIN TRANSACTION")
        try:
            for i in range(0, len(domainList), batch_size):
                batch = domainList[i:i + batch_size]
                placeholders = ','.join(['?'] * len(batch))
                sql = f"DELETE FROM {self.__table_domain} WHERE domain IN ({placeholders})"
                cursor = self.__conn.execute(sql, batch)
                total_deleted += cursor.rowcount
            self.__conn.commit()
        except Exception:
            self.__conn.rollback()
        return total_deleted


class DOMAIN(object):
    def __init__(self, domain: str, isBlock: int = None, timeStamp: int = None, ipList: str = None):
        self.domain = domain
        if timeStamp:
            self.__update = False
            self.__isBlock = isBlock
            self.__timeStamp = timeStamp
            self.__ipList = ipList.split(',') if ipList else []
        else:
            self.__update = True
            self.__isBlock = 0
            self.__timeStamp = int(time.time())
            self.__ipList = []

    def getTimeStamp(self) -> int:
        return self.__timeStamp

    def setBlock(self, isBlock: bool):
        f = 1 if isBlock else 0
        if self.__isBlock != f:
            self.__isBlock = f
            self.__timeStamp = int(time.time())
            self.__update = True

    def getBlock(self) -> bool:
        return bool(self.__isBlock)

    def setIPList(self, ipList: List[str]):
        self.__ipList = ipList
        self.__timeStamp = int(time.time())
        self.__update = True

    def getIPList(self) -> List[str]:
        return self.__ipList

    def getUpdate(self) -> bool:
        return self.__update

    def toTuple(self) -> Tuple:
        return (
            self.domain,
            self.__isBlock,
            self.__timeStamp,
            ','.join(map(str, self.__ipList)) if len(self.__ipList) else None,
        )


class BlackList(object):
    def __init__(self, path: str):
        self.__databaseFile = os.path.join(path, "domain.db")
        self.__blacklistFile = os.path.join(path, "rules/black.txt")
        self.__domainlistFile = os.path.join(path, "rules/domain.txt")
        self.__maxTask = 50

        self.__db = DomainDatabase(self.__databaseFile)

    def close(self):
        self.__db.close()

    def __getDomainDict(self) -> Dict[str, DOMAIN]:
        logger.info("resolve domain list...")
        domainDict = dict()
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r') as f:
                    for line in f.readlines():
                        line = line.replace('\r', '').replace('\n', '').strip()
                        if len(line) < 1:
                            continue
                        if line.startswith('#'):
                            continue
                        domainDict[line] = DOMAIN(line)
            logger.info("domain dict: %d" % len(domainDict))
            return domainDict
        except Exception as e:
            logger.error("%s" % e)
            return domainDict

    async def __resolve(self, dnsresolver, domain: str) -> List[str]:
        ipList = []
        for rdtype, rdataType in [("A", DNSRdataType.A), ("AAAA", DNSRdataType.AAAA)]:
            try:
                query_object = await dnsresolver.resolve(qname=domain, rdtype=rdtype)
                query_item = None
                for item in query_object.response.answer:
                    if item.rdtype == rdataType:
                        query_item = item
                        break
                if query_item is None:
                    continue
                for item in query_item:
                    ip = '{}'.format(item)
                    if ip not in ("0.0.0.0", "::"):
                        ipList.append(ip)
            except Exception as e:
                logger.error('"%s" (%s): %s' % (domain, rdtype, e if e else "Resolver failed"))
        return ipList

    async def __pingx(self, dnsresolver: DNSResolver, domain: DOMAIN, semaphore):
        async with semaphore:
            ipList = await self.__resolve(dnsresolver, domain.domain)
            domain.setIPList(ipList)
            logger.info("%s: %s" % (domain.domain, ipList if ipList else "DEAD"))
            return domain

    def __generateBlackList(self, blackList):
        logger.info("generate black list...")
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            with open(self.__blacklistFile, "w") as f:
                for domain in blackList:
                    f.write("%s\n" % domain)
            logger.info("black domain: %d" % len(blackList))
        except Exception as e:
            logger.error("%s" % e)

    def __testDomain(self, domainDict: Dict[str, DOMAIN], nameservers: str, port=53):
        logger.info("resolve domain...")

        async def _resolve_all():
            dnsresolver = DNSResolver()
            dnsresolver.nameservers = nameservers
            dnsresolver.port = port
            semaphore = asyncio.Semaphore(self.__maxTask)

            tasks = []
            now = int(time.time())
            for _, v in domainDict.items():
                ipList = v.getIPList()
                if len(ipList) < 1:
                    tasks.append(self.__pingx(dnsresolver, v, semaphore))
                else:
                    if now - v.getTimeStamp() > 1209600:
                        tasks.append(self.__pingx(dnsresolver, v, semaphore))
            results = await asyncio.gather(*tasks)

            for domain in results:
                domainDict[domain.domain] = domain

            logger.info("resolve domain: %d" % len(domainDict))
            return domainDict

        return asyncio.run(_resolve_all())

    def __getDomainDict_db(self, domainDict: Dict[str, DOMAIN]) -> Tuple[Dict[str, DOMAIN], List[str]]:
        logger.info("get domain list from db...")
        deleteList = list()
        try:
            for line in self.__db.getAll():
                if line[0] in domainDict:
                    domainDict[line[0]] = DOMAIN(line[0], line[1], line[2], line[3])
                else:
                    deleteList.append(line[0])
            logger.info("domain dict: %d" % len(domainDict))
            return domainDict, deleteList
        except Exception as e:
            logger.error("%s" % e)
            return domainDict, deleteList

    def __updateDomainDict_db(self, domainDict: Dict[str, DOMAIN]):
        logger.info("update domain list to db...")
        try:
            L = [v.toTuple() for _, v in domainDict.items() if v.getUpdate()]
            if len(L):
                self.__db.updateALL(L)
        except Exception as e:
            logger.error("%s" % e)

    def __deleteDomian_db(self, domainList: List[str]):
        logger.info("delete domain from db...")
        try:
            self.__db.deleteBatch(domainList)
        except Exception as e:
            logger.error("%s" % e)

    def generate(self):
        try:
            domainDict = self.__getDomainDict()
            if len(domainDict) < 1:
                return

            domainDict, deleteList = self.__getDomainDict_db(domainDict)
            domainDict = self.__testDomain(domainDict, ["127.0.0.1"], 5053)

            blackList = []
            for k, v in domainDict.items():
                ipList = v.getIPList()
                if len(ipList) == 0:
                    v.setBlock(True)
                    blackList.append(k)
                else:
                    v.setBlock(False)
            if len(blackList):
                blackList.sort()
                self.__generateBlackList(blackList)

            self.__updateDomainDict_db(domainDict)

            if len(deleteList):
                self.__deleteDomian_db(deleteList)

        except Exception as e:
            logger.error("%s" % e)


if __name__ == "__main__":
    path = os.getcwd()
    blackList = BlackList(path)
    blackList.generate()
    blackList.close()
