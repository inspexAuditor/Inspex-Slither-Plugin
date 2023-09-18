from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.utils.output import Output
from slither.utils.erc import (
    ERC20_signatures,
    ERC165_signatures,
    ERC223_signatures,
    ERC721_signatures,
    ERC1820_signatures,
    ERC777_signatures,
    ERC1155_signatures,
    ERC2612_signatures,
    ERC1363_signatures,
    ERC4524_signatures,
    ERC4626_signatures,
)


class StandardTokenCheck(AbstractDetector):

    ARGUMENT = "common-standard-token"
    HELP = "Assume the standard of the contract"

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://docs.inspex.co/smart-contract-security-testing-guide/testing-categories/2-testing-contract-compiling#2.1.-contract-dependency"

    WIKI_TITLE = "Assume the standard of the contract"
    WIKI_DESCRIPTION = "Assume the standard of the contract from the current implementation"


    WIKI_EXPLOIT_SCENARIO = """
```solidity

```"""

    WIKI_RECOMMENDATION = "The call that intents to be an internal call should not use this to refer to the function"

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        for c in self.contracts:
            res = self.guessERC(c)
            if res != []:
                results.append(self.generate_result(res))
            pass
        return results

    def guessERC(self, c: Contract):
        isERC = c.ercs()
        if len(isERC) > 0:
            return ['- ', c, f' contract is detected as {",".join(isERC)}\n']
        full_names = c.functions_signatures
        all_erc = [
            ["ERC20",   sum(s in full_names for s in ERC20_signatures), len(ERC20_signatures)],
            ["ERC165",  sum(s in full_names for s in ERC165_signatures), len(ERC165_signatures)],
            ["ERC1820", sum(s in full_names for s in ERC1820_signatures), len(ERC1820_signatures)],
            ["ERC223",  sum(s in full_names for s in ERC223_signatures), len(ERC223_signatures)],
            ["ERC721",  sum(s in full_names for s in ERC721_signatures), len(ERC721_signatures)],
            ["ERC777",  sum(s in full_names for s in ERC777_signatures), len(ERC777_signatures)],
            ["ERC1155", sum(s in full_names for s in ERC1155_signatures), len(ERC1155_signatures)],
            ["ERC2612", sum(s in full_names for s in ERC2612_signatures), len(ERC2612_signatures)],
            ["ERC1363", sum(s in full_names for s in ERC1363_signatures), len(ERC1363_signatures)],
            ["ERC4524", sum(s in full_names for s in ERC4524_signatures), len(ERC4524_signatures)],
            ["ERC4626", sum(s in full_names for s in ERC4626_signatures), len(ERC4626_signatures)],
        ]
        filtered_erc = list(filter(lambda x: x[1]/x[2]>=0.8, all_erc)) # Match more than 80 percent 
        filtered_erc = sorted(filtered_erc,key= lambda x: x[1]/x[2], reverse=True)
        if len(filtered_erc) > 0:
            erc = filtered_erc.pop(0)
            return ['- ', c, f' contract matchs {erc[1]} in {erc[2]} of the {erc[0]} required functions\n']
        return ['- ', c, f' contract not match the following standards: {",".join([e[0] for e in all_erc])}\n']