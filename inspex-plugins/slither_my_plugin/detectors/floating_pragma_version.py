from pprint import pprint
from typing import List
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable

class FloatingPragmaVersion(AbstractDetector, SummaryTable):

    ARGUMENT = "floating-pragma-version"
    HELP = "Using of Improper Pragma Version"

    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://inspex.gitbook.io/testing-guide/testing-items/9-best-practices#9.3.-floating-pragma-version-should-not-be-used"

    WIKI_TITLE = "Floating pragma version should not be used"
    WIKI_DESCRIPTION = "Smart contract compiler version can be specified using a floating pragma version; however, that may allow the contract to be compiled with other compiler versions than the one intended by the authors."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
// SPDX-License-Identifier: MIT

pragma solidity >=0.4.0 < 0.6.0;
pragma solidity >=0.4.0<0.6.0;
pragma solidity >=0.4.14 <0.6.0;
pragma solidity >0.4.13 <0.6.0;
pragma solidity 0.4.24 - 0.5.2;
pragma solidity >=0.4.24 <=0.5.3 ~0.4.20;
pragma solidity <0.4.26;
pragma solidity ~0.4.20;
pragma solidity ^0.4.14;
pragma solidity 0.4.*;
pragma solidity 0.*;
pragma solidity *;
pragma solidity 0.4;
pragma solidity 0;
```"""

    WIKI_RECOMMENDATION = "Change the compiler version flag to one fixed version."

    def _detect(self) -> List[Output]:
        results: List[Output] = []
        pragmas = self.compilation_unit.pragma_directives
        if len(pragmas) < 1:
            return results
        floating_char_detect = ['>', '<', '*', '^', '~', '-']
        info = []
        for p in pragmas:
            for fcd in floating_char_detect:
                if fcd in str(p):
                    if info == []:
                        info += ["Floating pragma version:\n"]
                    info += ["\t- ", p, "\n"]
                    break
        results.append(self.generate_result(info))
        return results

    def _toTable(self):
        """"
        example:
        | File | Contract | Function |
        ------------------------------
        """
        ### ---------------edit here---------------
        header = ["File", "Version"]
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
                    version = e["name"]
                    ### Map to row
                    row.append(file)
                    row.append(version)
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
