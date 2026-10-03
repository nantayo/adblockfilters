import time
from typing import List
from abc import ABC, abstractmethod

from loguru import logger

class APPBase(ABC):
    def __init__(self, blockList: List[str], unblockList: List[str], fileName: str, sourceRule: str):
        self.homepage = "https://github.com/nantayo/adblockfilters"
        self.source = "https://raw.githubusercontent.com/nantayo/adblockfilters/main/rules"
        self.version = time.strftime("%Y%m%d%H%M%S", time.localtime())
        self.time = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
        self.blockList = blockList
        self.unblockList = unblockList
        self.fileName = fileName
        self.sourceRule = sourceRule

    @abstractmethod
    def generate(self):
        pass

    def generateAll(self):
        try:
            if len(self.blockList):
                self.generate()
        except Exception as e:
            logger.error("%s" % e)
