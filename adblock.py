import os

from loguru import logger
from tld.utils import update_tld_names

from readme import ReadMe
from updater import Updater
from filter import Filter

class ADBlock(object):
    def __init__(self):
        self.pwd = os.getcwd()

    def refresh(self):
        readme = ReadMe(self.pwd + '/README.md')
        ruleList = readme.getRules()

        # 更新上游规则
        updater = Updater(ruleList)
        update, ruleList = updater.update(self.pwd + '/rules')
        if not update:
            return
        
        # 生成新规则
        filter = Filter(ruleList, self.pwd + '/rules')
        filter.generate(readme.getRulesNames())
        
        # 生成 README.md
        readme.setRules(ruleList)
        readme.regenerate()
        
if __name__ == '__main__':
    # 更新 tld
    update_tld_names()
    
    adBlock = ADBlock()
    adBlock.refresh()
