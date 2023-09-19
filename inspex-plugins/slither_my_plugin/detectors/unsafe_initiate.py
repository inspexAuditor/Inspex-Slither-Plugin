from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract, Modifier
from slither.core.cfg.node import Node
from slither.utils.output import Output


class UnsafeInitiate(AbstractDetector):

    ARGUMENT = "unsafe-initiate"
    HELP = "Find the initialize() function without any access control"

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://docs.inspex.co/smart-contract-security-testing-guide/testing-categories/9-testing-contract-upgradability#9.2.-the-initialize-function-implementation"

    WIKI_TITLE = "The initialize function could only be executed once by the authorized party"
    WIKI_DESCRIPTION = "It is important that the initialization be done only once by the authorized account to prevent the contract states from being overwritten"


    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Initialize {
    address public owner;

    function initialize() external {
        owner = msg.sender;
    }

    function withdraw(address to, uint256 amount) external {
        require(msg.sender == owner, "Only the owner can withdraw");
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```"""

    WIKI_RECOMMENDATION = "Enforce access control on the initialize() function"

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            res = self.findInitFunc(c)
            if res != []:
                results.append(self.generate_result(res))
            pass
        return results

    def findInitFunc(self, contract: Contract):
        res = []
        for f in contract.functions:
            safeFlag = False
            n: Node
            if 'initial' in f.name.lower(): # Loosen function name matching criteria
                if f.is_protected(): # The function has the basic access control
                    safeFlag = True
                    continue
                for m in f.modifiers:
                    safeFlag = self.modifierHandle(m) or safeFlag
                safeFlag = self.modifierHandle(f) or safeFlag

                if not safeFlag:
                    res += ['\t', f, '\n']
        return res
    
    def modifierHandle(self, m: Modifier) -> bool: 
        # for i in m.all_conditional_solidity_variables_read(): # if modifier read msg.sender
        #     if i._name == 'msg.sender':
        #         return True
        return self.selfReadWrite(m)

    @staticmethod
    def selfReadWrite(f) -> bool: 
        for v in f.all_conditional_state_variables_read(): # assume the it read & write the same state to check  the initiate condition. We cant assume the iniate state name. Or we should?
            if v in f.all_state_variables_written():
                return True
        return False