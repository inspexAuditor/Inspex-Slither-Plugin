from pprint import pprint
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.core.expressions.call_expression import CallExpression
from slither.utils.output import Output
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class SelfInvocation(AbstractDetector):

    ARGUMENT = "this-usage"
    HELP = "Using of to invoke internal function instead of jump"

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "Au's challenge"

    WIKI_TITLE = "Using this to invoke internal function"
    WIKI_DESCRIPTION = "Using this this to invoke internal create an external call to itself, which change the msg.sender state"


    WIKI_EXPLOIT_SCENARIO = """
```solidity
function buy(uint256 offerId) public {
    Offer storage offer = idToOffer[offerId];
    require(offer.status == Status.CREATED, "invalid status");
    offer.status = Status.SWAPPED;
    IERC20(offer.buyToken).transferFrom(msg.sender, offer.owner, offer.buyAmount);
    IERC721(offer.sellToken).transferFrom(address(this), msg.sender, offer.sellId);
}

function bulkBuy(uint256[] calldata offerIds) public {
    for (uint256 i = 0; i < offerIds.length; ++i) {
        this.buy(offerIds[i]);
    }
}
```"""

    WIKI_RECOMMENDATION = "The call that intents to be an internal call should not use this to refer to the function"

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            # if c.name != 'SimpleNFTMarketplace':
                # continue
            res = self.findAssert(c)
            if res != []:
                results.append(self.generate_result(res))
        return results

    def findAssert(self, contract: Contract):
        res = []
        for f in contract.functions:
            # if f.name != 'bulkOffer':
            #     continue
            for n in f.nodes:
                # print(n.type)
                detect = self.hasThis(n)
                if detect != None:

                # if n.expression and "assert" in str(n.expression):
                    if res == []:
                        res = ["Found this usage in ", contract, ":\n"]
                    res += ["\t- ", detect, "\n"]
        return res

    def hasThis(self, _node):
        # print(_node)
        if(str(_node.type) == "EXPRESSION"):
            # isinstance(_node.expression, CallExpression)
            if "this." in str(_node).lower(): # Crude but should do the trick
                return _node
        return None

    # def _toTable(self):
    #     """"
    #     example:
    #     | File | Contract | Function |
    #     ------------------------------
    #     """
    #     ### ---------------edit here---------------
    #     header = ["File", "Contract"]
    #     ### ---------------------------------------
        
    #     try:
    #         table = [header]
    #         column_max_len = [len(h) for h in header]
    #         detect_results = self._detect()
    #         for r in detect_results:
    #             row = []
    #             for e in r.elements:
    #                 # pprint(e)
    #                 ### ---------------edit here---------------
    #                 ### Get data from object
    #                 line = e['source_mapping']['lines'][0]
    #                 file = "%s (L:%s)" % (e["source_mapping"]["filename_short"].split("/")[-1], line)
    #                 contract = e["type_specific_fields"]["parent"]["name"]
    #                 # function = e["name"] + "()"
    #                 ### Map to row
    #                 row.append(file)
    #                 row.append(contract)
    #                 # row.append(function)
    #                 ### ---------------------------------------
    #                 ### Check max len
    #                 for i in range(len(row)):
    #                     column_max_len[i] = column_max_len[i] if column_max_len[i] > len(row[i]) else len(row[i])
    #                 table.append(row)
    #                 break
    #         return markdownTableFromSlitherResult(table, column_max_len, header[0])
    #     except Exception as e:
    #         pprint(e)
    #         return ""