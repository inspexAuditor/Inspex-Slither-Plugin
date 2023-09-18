from pprint import pprint
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.core.expressions.call_expression import CallExpression
from slither.utils.output import Output
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class SelfInvocation(AbstractDetector):

    ARGUMENT = "example-detector"
    HELP = ""

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = ""

    WIKI_TITLE = ""
    WIKI_DESCRIPTION = ""


    WIKI_EXPLOIT_SCENARIO = """
```solidity

```"""

    WIKI_RECOMMENDATION = "The call that intents to be an internal call should not use this to refer to the function"

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            # if c.name != 'SimpleNFTMarketplace':
                # continue
            # res = self.findAssert(c)
            # if res != []:
            #     results.append(self.generate_result(res))
            pass
        return results
