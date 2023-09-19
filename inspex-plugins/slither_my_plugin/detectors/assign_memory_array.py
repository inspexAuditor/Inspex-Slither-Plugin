
import pprint
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class AssignMemoryArray(AbstractDetector, SummaryTable):

    ARGUMENT = "assign-memory-array"
    HELP = "Assign the value to the memory of array"

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/5-blockchain-data#5.5.-modification-of-array-state-should-not-be-done-by-value"

    WIKI_TITLE = "Modification of array state should not be done by value"
    WIKI_DESCRIPTION = "Array state can be passed into a function by reference or by value, using the storage or memory keywords respectively. If the state is aimed to be modified, it should not be passed by value."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Memory {
    uint[1] public array;

    function set() public {
        setStorage(array); // update array
        setMemory(array); // do not update array
    }

    function setStorage(uint[1] storage arr) internal { // by reference
        arr[0] = 100;
    }

    function setMemory(uint[1] memory arr) internal { // by value
        arr[0] = 200;
    }
}
```"""

    WIKI_RECOMMENDATION = "Modify the array state by passing the parameter by reference using the storage keyword."


    def findMemoryArray(self, contract: Contract):
        res = []

        for f in contract.functions:
            if f.view or f.pure:
                continue
            for node in f.nodes:
                for ex in node._expression_vars_written:
                    if hasattr(ex, 'value'):
                        if hasattr(ex.value.type, '_length') and hasattr(ex.value, '_location'):
                            if ex.value.location == 'memory':
                                res.append(node)

        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findMemoryArray(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has expression(s) that assigns a value into a memory of array:\n"]
            for v in values:
                info += ["\t- ", v, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results

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