
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class InvokeUnknownExternalFunctions(AbstractDetector, SummaryTable):

    ARGUMENT = "unknown-external-functions"
    HELP = "Invoke unknow external function"

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/6-external-components#6.1.-unknown-external-components-should-not-be-invoked"

    WIKI_TITLE = "Unknown external components should not be invoked"
    WIKI_DESCRIPTION = "Check that only known and trusted contracts are invoked."

    WIKI_EXPLOIT_SCENARIO = """
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IRouter {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

contract UnsafeVault {
    using SafeERC20 for IERC20;
    mapping(address => uint256) public balances;
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    function swapAndDeposit(IRouter router, IERC20 srcToken, uint256 amount, uint256 amountOutMin) external {
        srcToken.safeTransferFrom(msg.sender, address(this), amount);
        address[] memory path;
        path[0] = address(srcToken);
        path[1] = address(token);
        srcToken.safeIncreaseAllowance(address(router), amount);
        uint256[] memory amounts = router.swapExactTokensForTokens(amount, amountOutMin, path, address(this), block.timestamp);
        balances[msg.sender] += amounts[1];
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

    WIKI_RECOMMENDATION = "Perform external callings to only known and trusted smart contracts, or define a whitelist of trustable contracts."


    def findExternal(self, contract: Contract):
        res = []

        for f in contract.functions:
            if f.view or f.pure:
                continue
            if f.is_implemented and f.name != 'constructor':
                for node in f.nodes:
                    if len(node.external_calls_as_expressions) > 0:
                        if 'expression' in node.external_calls_as_expressions[0].called.__dict__:
                            called = str(node.external_calls_as_expressions[0].called.expression)
                            for param in f.parameters:
                                if str(param) == called:
                                    res.append(node)

        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findExternal(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has function(s) that make external call(s) to unsafe address(es):\n"]
            for v in values:
                info += ["\t- ", v, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
