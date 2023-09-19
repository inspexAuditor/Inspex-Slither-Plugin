from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.expression import Expression
from slither.utils.output import Output
from slither.core.cfg.node import Node, NodeType


class DirtyIterators(AbstractDetector):

    ARGUMENT = "dirty-iterators"
    HELP = "Find loops that modifying its iterator"

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://docs.inspex.co/smart-contract-security-testing-guide/testing-categories/8-testing-loop-operation#8.5.-inconsistent-loop-iterator"

    WIKI_TITLE = "Having multiple expression that alter the same iterator of the loop"
    WIKI_DESCRIPTION = "Having multiple places that change the iterator could lead to unintended behavior in the contract."


    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Buggy {
    uint[] public myNumber;

    function sumOfEvenElement() public returns (uint256){
        uint256 total = 0;
        for (uint i; i < myNumber.length - 1; i++) {
            if (i % 2 == 0) {
                total = total + myNumber[i];
                i++;
            }
        }
        return total;
    }
}
```"""

    WIKI_RECOMMENDATION = "Make sure that the multiple of iterators are neccessary, if not, they should be only one place to modify it"

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
            iterators = []
            for n in f.nodes:
                if n._node_type == NodeType.IFLOOP: # Not work in nested loop case
                    isInLoop = True
                    if isinstance(n.expression, BinaryOperation) and hasattr(n.expression, '_expressions'):
                        for ex in n.expression._expressions:
                            if isinstance(ex, Identifier):
                                iterators.append([ex._value,[]])

                elif  hasattr(n.immediate_dominator, '_node_type') and n.immediate_dominator.type  == NodeType.ENDLOOP:
                    isInLoop = False
                if isInLoop:
                    if n.type == NodeType.EXPRESSION:
                        e: Expression
                        e = n.expression
                        if hasattr(e, '_expression'):
                            if e._expression._is_lvalue:
                                for i, it in enumerate(iterators):
                                    if e._expression._value == it[0]:
                                        if iterators[i][1] == []:
                                            iterators[i][1] += [ f, "\n"]
                                        iterators[i][1] += ["\t", n, "\n"]
            for it in iterators:
                if len(it[1]) > 5: # If has multiple modifying | 2 for function offset + 3 for each modifying
                    res += it[1]
        return res
        