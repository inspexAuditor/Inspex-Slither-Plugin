from pprint import pprint
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult
from slither_my_plugin.detectors.extends.summary_table import SummaryTable
from slither.detectors.attributes.incorrect_solc import IncorrectSolc

class InspexIncorrectSolc(IncorrectSolc,  SummaryTable):
    ARGUMENT = "inspex-solc-version"


    def _detect(self):
        """
        Detects pragma statements that allow for outdated solc versions.
        :return: Returns the relevant JSON data for the findings.
        """
        # Detect all version related pragmas and check if they are disallowed.
        results = []
        pragma = self.compilation_unit.pragma_directives
        disallowed_pragmas = []

        for p in pragma:
            # Skip any pragma directives which do not refer to version
            if len(p.directive) < 1 or p.directive[0] != "solidity":
                continue

            # This is version, so we test if this is disallowed.
            reason = self._check_pragma(p.version)
            if reason:
                disallowed_pragmas.append((reason, p))

        # If we found any disallowed pragmas, we output our findings.
        if disallowed_pragmas:
            for (reason, p) in disallowed_pragmas:
                info = ["Pragma version", p, f" {reason}\n"]
                # pprint(p.__dict__)
                json = self.generate_result(info)

                results.append(json)

        if self.compilation_unit.solc_version not in self.ALLOWED_VERSIONS:

            if self.compilation_unit.solc_version in self.BUGGY_VERSIONS:
                info = [
                    "solc-",
                    self.compilation_unit.solc_version,
                    " ",
                    self.BUGGY_VERSION_TXT,
                ]
            else:
                info = [
                    "solc-",
                    self.compilation_unit.solc_version,
                    " is not recommended for deployment\n",
                ]

            json = self.generate_result(info)

            # TODO: Once crytic-compile adds config file info, add a source mapping element pointing to
            #       the line in the config that specifies the problematic version of solc

            results.append(json)

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