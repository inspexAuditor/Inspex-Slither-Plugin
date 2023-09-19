
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class InexplicitVariableVisibility(AbstractDetector, SummaryTable):

    ARGUMENT = "inexplicit-variable-visibility"
    HELP = "State variable should have explicit visibility"

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/9-best-practices#9.1.-state-and-function-visibility-should-be-explicitly-labeled"

    WIKI_TITLE = "State and function visibility should be explicitly labeled"
    WIKI_DESCRIPTION = "Check that all state variables and functions have explicit visibility."

    WIKI_EXPLOIT_SCENARIO = """
contract Visibility {
    uint256 state;

    function setState(uint256 newState) {
        state = newState;
    }

    function getState() view returns (uint256) {
        return state;
    }

}
"""

    WIKI_RECOMMENDATION = "Explicitly label the visibility of the state variables and functions."


    def findStateviables(self, contract: Contract):
        res = []

        for sv in contract.variables:
            if sv.visibility == 'internal':
                res.append(sv)

        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findStateviables(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has state variable(s) that inexplicitly defined visibility:\n"]
            for v in values:
                info += ["\t- ", v, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
