from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither.core.cfg.node import Node, NodeType


class LoopSkip(AbstractDetector):

    ARGUMENT = "loop-skip"
    HELP = "Find a potentially flow control breaking in loops"

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://docs.inspex.co/smart-contract-security-testing-guide/testing-categories/8-testing-loop-operation#8.4.-using-flow-control-expressions-over-loop-execution"

    WIKI_TITLE = "Using flow control expressions over loop execution"
    WIKI_DESCRIPTION = "Using continue, break, and return incorrectly can potentially lead to business logic errors or unintended behavior in the code."


    WIKI_EXPLOIT_SCENARIO = """
```solidity
function registerToken(address[] memory tokens) external {
    for(uint256 i; i<tokens.length ; i++) {
        if(tokens[i] == address(0)) {
            return; // the return terminate the whole function, not just the loop 
        }
        registeredToken.push(tokens[i]);
    }
}
```"""

    WIKI_RECOMMENDATION = "Remove the flow controls that skip the critical executions."

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            res = self.findLoop(c)
            if res != []:
                results.append(self.generate_result(res))
            pass
        return results
    
    def findLoop(self, contract: Contract):
        res = []
        for f in contract.functions:
            n: Node
            isInLoop = False
            for n in f.nodes:
                if n._node_type == NodeType.IFLOOP: # Not work in nested loop case
                    isInLoop = True
                if  hasattr(n.immediate_dominator, '_node_type') and n.immediate_dominator._node_type  == NodeType.ENDLOOP:
                    isInLoop = False
                if isInLoop:
                    if n._node_type in [NodeType.RETURN, NodeType.BREAK, NodeType.CONTINUE]:
                        res += ["\t- ", n, "\n"]
        return res

    