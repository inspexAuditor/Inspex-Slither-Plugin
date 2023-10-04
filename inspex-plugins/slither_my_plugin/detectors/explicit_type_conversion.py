from typing import List
from slither.core.cfg.node import Node
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither.core.expressions.type_conversion import TypeConversion
from slither_my_plugin.detectors.extends.summary_table import SummaryTable

class ExplicitTypeConversion(AbstractDetector, SummaryTable):

    ARGUMENT = "explicit-type-conversion"
    HELP = "Incorrect Type Conversion or Cast" 

    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.MEDIUM   

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/7-arithmetic#7.2.-explicit-conversion-of-types-should-be-checked-to-prevent-unexpected-results"

    WIKI_TITLE = "Explicit conversion of types should be checked to prevent unexpected results"
    WIKI_DESCRIPTION = "Data type of a variable can be cast to another type explicitly; however, if the destination type cannot hold the values of the original variable, unexpected values can be yielded from the truncation or padding."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Cast {
    uint128 public pricePerItem;
    mapping(address => uint256) public balances;

    constructor(uint128 _pricePerItem) {
        pricePerItem = _pricePerItem;
    }

    function buy(uint amount) external payable {
        uint128 price = uint128(pricePerItem * amount);
        require(msg.value >= price);
        balances[msg.sender] += amount;
    }
}
```""" 

    WIKI_RECOMMENDATION = "Perform conditional checking to make sure that the whole range of possible values is supported."

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            res = self.findExplicit(c)
            if res: # is the result not empty
                if results: #is the title was set
                    results.append(self.generate_result(res))
                else:
                    results.append(self.generate_result(["Please verify the type conversion at the following items:\n"]))
                    results.append(self.generate_result(res))
        return results

    def has_type_conversion(self, node: Node):
        res = []
        if node.expression and "_expressions" in node.expression.__dict__:
            for e in node.expression.expressions:
                if isinstance(e, TypeConversion):
                    if("_type" in e.__dict__ and e._type is not None):
                        if str(e._type) != "address":
                            res += ["\t- ", node, "\n"]

    def findExplicit(self, contract: Contract):
        res = []
        for f in contract.functions:
            for n in f.nodes:
                res += self.has_type_conversion(n)
        return res
