from pprint import pprint
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import FunctionContract
from slither.utils.output import Output
from slither.core.expressions.call_expression import CallExpression
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable
from slither_my_plugin.detectors.extends.privilege_list import PrivilegeList


class CentralizedState(AbstractDetector, SummaryTable, PrivilegeList):

    ARGUMENT = "centralized-state"
    HELP = "Centralized Control of State Variable"

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/1-architecture-and-design#1.5.-state-variables-should-not-be-unfairly-controlled-by-privileged-accounts"

    WIKI_TITLE = "State variables should not be unfairly controlled by privileged accounts"
    WIKI_DESCRIPTION = "Only the states that require modifications by the privileged parties should be modifiable by the admin accounts. The admin accounts should have the least privilege possible to manage the operation of the smart contracts. With overly permissive rights, the privileged accounts can perform actions that are unfair to the smart contract users to gain benefits."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Owner {
    address private owner;
    uint256 fee;
    constructor() {
        owner = msg.sender;
    }

    modifier isOwner() {
        require(msg.sender == owner, "Only the owner can call this function.");
        _;
    }
    function changeOwner(address _owner) isOwner external {
        owner = _owner;
    }

    function setFee(uint256 _fee) isOwner external {
        fee = _fee;
    }

    function withdraw() external {
        require(msg.sender == owner, "Only owner can withdraw");
        (bool sent, bytes memory data) = payable(msg.sender).call{value: address(this).balance}("");
        require(sent, "Failed to send Ether");
    }
}
```"""

    WIKI_RECOMMENDATION = "Remove the functions with unnecessarily high privilege; Transfer the privilege to community-run smart contract governance or DAO. Mitigate the risk by using a timelock to delay the effect of the privileged functions by a sufficient amount of time, e.g. at least 24 hours."

    def is_required_msg_sender(self, expression: CallExpression):
        if 'require' in str(expression.called) or 'assert' in str(expression.called):
            expName = expression.called.value.name.split('(')[0]
            if expName in ['require', 'assert'] and hasattr(expression.arguments[0], 'expressions'):
                arg0 = expression.arguments[0].expressions[0]
                arg1 = expression.arguments[0].expressions[1]
                if 'sender' in str(arg0) or 'sender' in str(arg1):
                    return True
        return False

    def is_centralized_modifier(self, modifier: FunctionContract):
        for n in modifier.nodes:
            if isinstance(n.expression, CallExpression):
                return self.is_required_msg_sender(n.expression)
        return False
    
    def gen_state_change_info(self, func: FunctionContract):
        info = []
        for v in func.state_variables_written:
            info += ["\t- ", v, "\n"]
        return info

    def check_function(self, func: FunctionContract):
        res = []
        modifiers = []
        if len(func.modifiers) > 0:
            for m in func.modifiers:
                if 'isUsePrivilegeList' in self.__dict__ and self.isUsePrivilegeList:
                    if m.name in self.modifiers:
                        # res += ["- ", func, "\n"]
                        # res += ["  ", "**STATE CHANGE**", "\n"]
                        res.extend(self.gen_state_change_info(func))
                        modifiers.append(m)
                        continue
                else:
                    if self.is_centralized_modifier(m):
                        # res += ["- ", func, "\n"]
                        # res += ["  ", "**STATE CHANGE**", "\n"]
                        res.extend(self.gen_state_change_info(func))
                        modifiers.append(m)
                        continue
        else:
            for e in func.expressions:
                if isinstance(e, CallExpression) and self.is_required_msg_sender(e):
                    # res += ["- ", func, "\n"]
                    # res += ["  ", "**STATE CHANGE**", "\n"]
                    res.extend(self.gen_state_change_info(func))
                    continue
        return (res, modifiers)


    def isStateChanged(self, f:FunctionContract) -> bool:
        return len(f.state_variables_written)+len(f._high_level_calls) > 0 # a > 0 || b > 0

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            for f in c.functions_entry_points:
                if f.view or f.pure:
                    continue
                if self.isStateChanged(f):
                    (res, modifiers) = self.check_function(f)
                    if len(res) > 0:
                        results.append(self.generate_result(res, additional_fields={"modifiers": modifiers}))

        if len(results) > 0:
            results.insert(0, self.generate_result(["Centralized Control of State Variable \n"]))
        return results


    def _toTable(self):
        """"
        example:
        | File | Contract | Function |
        ------------------------------
        """
        ### ---------------edit here---------------
        header = ["File", "Contract", "Function",  "Modifier"]
        ### ---------------------------------------
        
        try:
            table = [header]
            column_max_len = [len(h) for h in header]
            detect_results = self._detect()
            
            for r in detect_results:
                row = []
                for e in r.elements:
                    ### ---------------edit here---------------
                    ### Get data from object
                    line = e['source_mapping']['lines'][0]
                    file = "%s (L:%s)" % (e["source_mapping"]["filename_short"].split("/")[-1], line)
                    contract = e["type_specific_fields"]["parent"]["name"]
                    function = e["name"] + "()"
                    modifiers = ", ".join([m.name for m in r.data['additional_fields']['modifiers'] ])
                    ### ---------------------------------------
                    ### Map to row
                    row.append(file)
                    row.append(contract)
                    row.append(function)
                    row.append(modifiers)
                    ### ---------------------------------------
                    ### Check max len
                    for i in range(len(row)):
                        column_max_len[i] = column_max_len[i] if column_max_len[i] > len(row[i]) else len(row[i])
                    table.append(row)
                    break
            return markdownTableFromSlitherResult(table, column_max_len)
        except Exception as e:
            pprint(e)
            return ""
