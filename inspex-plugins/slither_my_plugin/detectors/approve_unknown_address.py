
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither_my_plugin.detectors.extends.summary_table import SummaryTable


class ApproveUnknownAddress(AbstractDetector, SummaryTable):

    ARGUMENT = "approve-unknown-address"
    HELP = "Approve or Transfer to unknown address"

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/6-external-components#6.2.-funds-should-not-be-approved-or-transferred-to-unknown-accounts"

    WIKI_TITLE = "Funds should not be approved or transferred to unknown accounts"
    WIKI_DESCRIPTION = "Funds approved or transferred to an unknown account can be pulled from the contract anytime by the target account. Funds should only be transferred or approved to accounts within the trusted scope."

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

contract UnsafeVault2 {
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
        srcToken.approve(address(router), type(uint256).max);
        uint256[] memory amounts = router.swapExactTokensForTokens(amount, amountOutMin, path, address(this), block.timestamp);
        srcToken.approve(address(router), 0);
        balances[msg.sender] += amounts[1];
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

    WIKI_RECOMMENDATION = "Avoid approving or transferring funds to unknown accounts"


    def findApprove(self, contract: Contract):
        res = []

        for f in contract.functions:
            if f.view or f.pure:
                continue
            if f.is_implemented and f.name != 'constructor':
                for node in f.nodes:
                    if len(node.external_calls_as_expressions) > 0:
                        ext = node.external_calls_as_expressions[0]
                        if 'member_name' in ext.called.__dict__:
                            if ext.called.member_name == 'approve':
                                for arg in ext.arguments:
                                    for p in f.parameters:
                                        if str(p) in str(arg):
                                            res.append(node)
        return res


    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = self.findApprove(c)
            if len(values) == 0:
                continue
            info = [c.name, " contract has function(s) that approve address(es):\n"]
            for v in values:
                info += ["\t- ", v, "\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
