import os
from typing import List

from loguru import logger

from app.base import APPBase

class MosDNS(APPBase):
    def __init__(self, blockList: List[str], unblockList: List[str], fileName: str, sourceRule: str):
        super().__init__(blockList, unblockList, fileName, sourceRule)

    def generate(self):
        try:
            logger.info("generate adblock MosDNS...")
            fileName = self.fileName
            blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            with open(fileName, 'a', encoding='utf-8') as f:
                f.write("#\n")
                f.write("# Title: AdBlock MosDNS\n")
                f.write("# Description: 适用于 MosDNS 的去广告合并规则，每日更新一次。规则源：%s。\n" % self.sourceRule)
                f.write("# Homepage: %s\n" % self.homepage)
                f.write("# Source: %s/%s\n" % (self.source, os.path.basename(fileName)))
                f.write("# Version: %s\n" % self.version)
                f.write("# Last modified: %s\n" % self.time)
                f.write("# Blocked domains: %s\n" % len(blockList))
                f.write("#\n")
                for domain in blockList:
                    f.write("%s\n" % domain)

            logger.info("adblock MosDNS: block=%d" % len(blockList))
        except Exception as e:
            logger.error("%s" % e)
