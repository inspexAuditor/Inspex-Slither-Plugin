from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.analyses.data_dependency.data_dependency import is_dependent_ssa
from slither.core.declarations import Function
from slither.core.declarations.function_top_level import FunctionTopLevel
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    HighLevelCall,
    SolidityCall,
)
from slither.core.solidity_types import MappingType, ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityVariableComposed,
    SolidityFunction,
)
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable
from pprint import pprint


class StrictEqualities(AbstractDetector, SummaryTable):

    ARGUMENT = "strict-equalities"
    HELP = "Using of Improper Strict Equalities"

    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.LOW   

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/8-denial-of-services#8.3.-strict-equalities-should-not-cause-the-function-to-be-unusable"

    WIKI_TITLE = "Strict equalities should not cause the function to be unusable"
    WIKI_DESCRIPTION = "When determining the value of a state controllable by external actors, such as account balance, strict equality should not be used. This is because the state can be changed, such as by directly transfer to the contract, causing the function to be unusable."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
function goalReached() public returns(bool){
    return this.balance == 5 ether;
}
```""" 

    WIKI_RECOMMENDATION = "Use \"greater than or equal to\" or \"less than or equal to\" instead of strict equality for a state controllable by external actors to prevent denial of service."

    sources_taint = [
        SolidityVariable("now"),
        SolidityVariableComposed("block.number"),
        SolidityVariableComposed("block.timestamp"),
    ]

    @staticmethod
    def is_direct_comparison(ir):
        return isinstance(ir, Binary) and ir.type == BinaryType.EQUAL

    @staticmethod
    def is_any_tainted(variables, taints, function) -> bool:
        return any(
            (
                is_dependent_ssa(var, taint, function.contract)
                for var in variables
                for taint in taints
            )
        )

    def taint_balance_equalities(self, functions):
        taints = []
        for func in functions:
            for node in func.nodes:
                for ir in node.irs_ssa:
                    if isinstance(ir, SolidityCall) and ir.function == SolidityFunction(
                        "balance(address)"
                    ):
                        taints.append(ir.lvalue)
                    if isinstance(ir, HighLevelCall):
                        # print(ir.function.full_name)
                        if (
                            isinstance(ir.function, Function)
                            and ir.function.full_name == "balanceOf(address)"
                        ):
                            taints.append(ir.lvalue)
                        if (
                            isinstance(ir.function, StateVariable)
                            and isinstance(ir.function.type, MappingType)
                            and ir.function.name == "balanceOf"
                            and ir.function.type.type_from == ElementaryType("address")
                            and ir.function.type.type_to == ElementaryType("uint256")
                        ):
                            taints.append(ir.lvalue)
                    if isinstance(ir, Assignment):
                        if ir.rvalue in self.sources_taint:
                            taints.append(ir.lvalue)

        return taints

    # Retrieve all tainted (node, function) pairs
    def tainted_equality_nodes(self, funcs, taints):
        results = {}
        taints += self.sources_taint

        for func in funcs:
            # Disable the detector on top level function until we have good taint on those
            if isinstance(func, FunctionTopLevel):
                continue
            for node in func.nodes:
                for ir in node.irs_ssa:

                    # Filter to only tainted equality (==) comparisons
                    if self.is_direct_comparison(ir) and self.is_any_tainted(ir.used, taints, func):
                        if func not in results:
                            results[func] = []
                        results[func].append(node)

        return results

    def detect_strict_equality(self, contract):
        funcs = contract.all_functions_called + contract.modifiers

        # Taint all BALANCE accesses
        taints = self.taint_balance_equalities(funcs)

        # Accumulate tainted (node,function) pairs involved in strict equality (==) comparisons
        results = self.tainted_equality_nodes(funcs, taints)

        return results

    def _detect(self):
        results = []

        for c in self.compilation_unit.contracts_derived:
            ret = self.detect_strict_equality(c)

            # sort ret to get deterministic results
            ret = sorted(list(ret.items()), key=lambda x: x[0].name)
            for f, nodes in ret:

                func_info = [f, " uses a dangerous strict equality:\n"]

                # sort the nodes to get deterministic results
                nodes.sort(key=lambda x: x.node_id)

                # Output each node with the function info header as a separate result.
                for node in nodes:
                    node_info = func_info + ["\t- ", node, "\n"]

                    res = self.generate_result(node_info)
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