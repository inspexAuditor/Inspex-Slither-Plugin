
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.detectors.extends.summary_table import SummaryTable

class StateChangingLoop(AbstractDetector, SummaryTable):

    ARGUMENT = "state-changing-loop"
    HELP = "A loop contains a state changing expression"

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/8-denial-of-services#8.1.-state-changing-functions-that-loop-over-unbounded-data-structures-should-not-be-used"

    WIKI_TITLE = "State changing functions that loop over unbounded data structures should not be used"
    WIKI_DESCRIPTION = "Check that there is no action which requires looping over the entire unbounded data structure."

    WIKI_EXPLOIT_SCENARIO = """
function calculateInterests() public {
	for (uint i = 0; i < users.length; i++) {
		interests[users[i]] += calculateUserInterest(users[i]);
		depositTimes[users[i]] = block.timestamp;
	}
}

function calculateUserInterest(address user) public view returns (uint256) {
	if (balances[user] > 0) {
		return balances[user] * (block.timestamp - depositTimes[user]) / 3600;
	}
	return 0;
}
"""

    WIKI_RECOMMENDATION = "Avoid looping through the whole data structure with an unbounded size; or, if looping over the entire structure is required, separate the looping into multiple transactions over multiple blocks."


    def findLoop(self, contract: Contract):
        res = []

        for f in contract.functions:
            if f.view or f.pure:
                continue
            flag = False
            tmp = []
            if f.is_implemented and f.name != 'constructor':
                loopHeader = None
                for node in f.nodes:
                    if str(node._node_type) == 'IF_LOOP':
                        flag = True
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
                            if len(node._state_vars_written) > 0:
                                tmp.append(node)
            if len(tmp) > 0:
                res.append([f, tmp])

        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findLoop(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has function(s) that change the state variables expression(s) inside an unbound loop:\n"]
            for v in values:
                info += ["\t- ", v[0], "\n"]
                for sv in v[1]:
                    info += ["\t\t- ", sv, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
