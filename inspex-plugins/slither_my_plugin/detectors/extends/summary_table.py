from pprint import pprint
from slither_my_plugin.utils.table_generator import markdownTableFromSlitherResult


class SummaryTable:

    def toTable(self):

        if "_toTable" in dir(self):
            return self._toTable()

        header = ["File", "Contract", "Function"]
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
            """ If unexpected thing happen T.T """
            pprint(e)
            return ""