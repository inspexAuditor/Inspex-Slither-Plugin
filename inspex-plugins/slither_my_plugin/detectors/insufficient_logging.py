from typing import List
from slither.core.cfg.node import Node
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.slithir.operations.event_call import EventCall
from slither.utils.output import Output
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable
from pprint import pprint


def detect_privileged(contract: Contract) -> List[Node]:
    ret: List[Node] = []
    for f in contract.functions_entry_points:
        if f.view or f.pure:
            continue
        if f.is_implemented and len(f.modifiers) > 0 and f.name != 'constructor':
            emit = has_emit(f.entry_point, 0, [])
            # print(emit)
            if emit == 0:
                ret.append(f.entry_point)
    return ret


def has_emit(node: Node, emit: int, visited: List[Node]) -> int:
    if node in visited:
        return emit
    # shared visited
    visited.append(node)

    for ir in node.all_slithir_operations():
        if isinstance(ir, EventCall):
            emit += 1

    for son in node.sons:
        emit += has_emit(son, emit, visited)

    return emit


class InsufficientLogging(AbstractDetector, SummaryTable):

    ARGUMENT = "insufficient-logging"
    HELP = "Insufficient Logging"

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-categories/3-error-handling-and-logging#3.2.-privileged-functions-or-modifications-of-critical-states-should-be-logged"

    WIKI_TITLE = "Insufficient Logging for Privileged Functions"
    WIKI_DESCRIPTION = "Privileged functions' executions cannot be monitored easily by the users."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Lock {

    event Good();

    bool public state_variable = false;

    function bad() external onlyOwner {
        state_variable = true;
    }

    function good() external onlyOwner {
        state_variable = true;
        emit Good();
    }
}
```"""

    WIKI_RECOMMENDATION = "emit an event for users."

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = detect_privileged(c)
            for node in values:
                func = node.function
                info = [func, " no emit event:\n"]
                # info += ["\t- ", func, "\n"]
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
        header = ["File", "Contract", "Function"]
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
                    ### Map to row
                    row.append(file)
                    row.append(contract)
                    row.append(function)
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