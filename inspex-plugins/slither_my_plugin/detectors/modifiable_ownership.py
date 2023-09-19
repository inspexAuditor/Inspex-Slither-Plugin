from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class ModifiableOwnership(AbstractDetector, SummaryTable):

    ARGUMENT = "modifiable-ownership"
    HELP = "Unauthorized Modifiable Ownership"

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/2-access-control#2.2.-contract-ownership-should-not-be-modifiable-by-unauthorized-actors"

    WIKI_TITLE = "Contract ownership should not be modifiable by unauthorized actors"
    WIKI_DESCRIPTION = "Functions with the ability to transfer the ownership of the contract should have a proper access control measure implemented to prevent unauthorized parties from taking over the contract ownership."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Owner {
    address payable private owner;
    constructor() {
        owner = msg.sender;
    }
    function Bad_changeOwner(address _owner) external {
        require(msg.sender == _owner, "Only owner can transfer ownership");
        owner = _owner;
    }
    function Good_changeOwner(address _owner) external {
        require(msg.sender == owner, "Only owner can transfer ownership");
        owner = _owner;
    }
    function withdraw() external {
        require(msg.sender == owner, "Only owner can withdraw");
        (bool sent, bytes memory data) = msg.sender.call{value: 1}("");
        require(sent, "Failed to send Ether");
    }
}
```"""

    WIKI_RECOMMENDATION = "Implement an access control measure to allow only the authorized parties to manage the ownership of the contract."


    def findOwner(self, contract: Contract):
        res = []
        for f in contract.functions_entry_points:
            if f.view or f.pure:
                continue
            for n in f.state_variables_written:
                if 'owner' in n.name and f.name != 'constructor':
                    res.append(f)

        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findOwner(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has function(s) that modifies the ownership:\n"]
            for v in values:
                info += ["\t- ", v, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
