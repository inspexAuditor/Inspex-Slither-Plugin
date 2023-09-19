
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither.core.expressions.call_expression import CallExpression
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class LoopReverted(AbstractDetector, SummaryTable):

    ARGUMENT = "loop-reverted"
    HELP = "A loop of multiple element that could be reverted"

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/8-denial-of-services#8.2.-unexpected-revert-should-not-make-the-whole-smart-contract-unusable"

    WIKI_TITLE = "Unexpected revert should not make the whole smart contract unusable"
    WIKI_DESCRIPTION = "Check that no account can perform denial of service on the contract by reverting the transaction."

    WIKI_EXPLOIT_SCENARIO = """
function sendReward() external {
	require(!sent, "Reward sent");
	sent = true;
	for (uint i = 0; i < winnerList.length; i++) {
		(bool success, ) = winnerList[i].call{value: REWARD}("");
		require(success, "Transfer failed");
	}
}
"""

    WIKI_RECOMMENDATION = "Use the “Pull over Push” pattern (https://fravoll.github.io/solidity-patterns/pull_over_push.html) by changing the payment design to allow users to withdraw funds instead of sending funds to other accounts."


    def findLoopRevert(self, contract: Contract):
        res = []

        for f in contract.functions:
            flag = False
            tmp = []
            if f.is_implemented and f.name != 'constructor':
                loopHeader = None
                for node in f.nodes:
                    if str(node._node_type) == 'IF_LOOP':
                        flag = True
                        if 'expressions' in node.expression.__dict__:
                            for e in node.expression.expressions:
                                if "_member_name" in e.__dict__:
                                    if e.member_name == 'length':
                                        flag = True
                                        loopHeader = node
                                        break
                    if flag:
                        isInLoop = False
                        for d in node._dominance_frontier:
                            if loopHeader == d:
                                isInLoop = True
                                break
                        
                        if isInLoop:
                            if isinstance(node.expression, CallExpression):
                                if "_value" in node._expression_calls[0].called.__dict__:
                                    expName = node._expression_calls[0].called.value.name.split('(')[0]
                                    if expName in ['require', 'assert', 'revert']:
                                        tmp.append(node)

            if len(tmp) > 0:
                res.append([f, tmp])

        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findLoopRevert(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has function(s) that could revert inside a loop:\n"]
            for v in values:
                info += ["\t- ", v[0], "\n"]
                for sv in v[1]:
                    info += ["\t\t- ", sv, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
