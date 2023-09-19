from pprint import pprint
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class AssertStatement(AbstractDetector, SummaryTable):

    ARGUMENT = "assert-statement"
    HELP = "Using of Improper Statement Validator"

    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/9-best-practices#9.6.-assert-statement-should-not-be-used-for-validating-common-conditions"

    WIKI_TITLE = "Assert statement should not be used for validating common conditions"
    WIKI_DESCRIPTION = "The assert() statement is an overly assertive checking that drains all gas in the transaction when triggered. A properly functioning smart contract should never reach a failing assert statement. Instead, the require() statement should be used to validate that the conditions are met, or to validate return values from external contract callings."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
function withdraw(uint256 amount) external {
    assert(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    assert(success);
}
```"""

    WIKI_RECOMMENDATION = "Replace the assert() statement with require() statement if the condition checked is not an invariant or a condition that should be impossible to be reached."

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            res = self.findAssert(c)
            if res != []:
                results.append(self.generate_result(res))
        return results

    def findAssert(self, contract: Contract):
        res = []
        for f in contract.functions:
            for n in f.nodes:
                if n.expression and "assert" in str(n.expression):
                    if res == []:
                        res = ["Found assert statement in ", f, ":\n"]
                    res += ["\t- ", n, "\n"]
        return res

    def _toTable(self):
        """"
        example:
        | File | Contract | Function |
        ------------------------------
        """
        ### ---------------edit here---------------
        header = ["File", "Contract"]
        ### ---------------------------------------
        
        try:
            table = [header]
            column_max_len = [len(h) for h in header]
            detect_results = self._detect()
            for r in detect_results:
                row = []
                for e in r.elements:
                    # pprint(e)
                    ### ---------------edit here---------------
                    ### Get data from object
                    line = e['source_mapping']['lines'][0]
                    file = "%s (L:%s)" % (e["source_mapping"]["filename_short"].split("/")[-1], line)
                    contract = e["type_specific_fields"]["parent"]["name"]
                    # function = e["name"] + "()"
                    ### Map to row
                    row.append(file)
                    row.append(contract)
                    # row.append(function)
                    ### ---------------------------------------
                    ### Check max len
                    for i in range(len(row)):
                        column_max_len[i] = column_max_len[i] if column_max_len[i] > len(row[i]) else len(row[i])
                    table.append(row)
                    break
            return markdownTableFromSlitherResult(table, column_max_len, header[0])
        except Exception as e:
            pprint(e)
            return ""