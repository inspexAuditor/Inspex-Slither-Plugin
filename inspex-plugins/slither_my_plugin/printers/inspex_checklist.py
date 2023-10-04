from slither.printers.abstract_printer import AbstractPrinter
from pathlib import Path
import xlsxwriter
import csv
import re

STANDARD_ISSUES = [
        [ "1. Testing Arithmetic Operation and Conversion",
        ["1.1	Integer Overflow and Underflow",
        ["1.1.1	Solidity compiler version 0.8.0 and higher", []],
        ["1.1.2	Solidity compiler version 0.8.0 and below", [] ]],
        ["1.2	Precision Loss" ,
        ["1.2.1	The rounding down of the division", [] ],
        ["1.2.2	The order of division and multiplication", ['divide-before-multiply'] ]],
        ["1.3	Type conversion",
        ["1.3.1	The change of size (Same type with different size conversion)", ['explicit-type-conversion'] ],
        ["1.3.2	The change of type (Different types with the same size conversion)", [] ],
        ["1.3.3	The change of sign (Different sign conversion)", [] ]]],

        [ "2. Testing Contract Compiling",
        ["2.1	Contract dependency",
        ["2.1.1	Contract implementation should comply with the standards specification", ['erc20-interface', 'erc721-interface', 'common-standard-token'] ],
        ["2.1.2	Built-in symbols should not be shadowed", ['shadowing-builtin', 'shadowing-abstract', 'shadowing-state'] ]],
        ["2.2	Solidity",
        ["2.2.1	Solidity compiler version should be specific", ['floating-pragma-version'] ],
        ["2.2.2	State and function visibility should be explicitly labeled", ['inexplicit-variable-visibility'] ],
        ["2.2.3	Functions that are never called internally should not have public visibility", ['external-function'] ]]],

        [ "3. Testing External Interaction", 
        ["3.1	Invoking external calls",
        ["3.1.1	Unknown external components should not be invoked", ['unknown-external-functions'] ],
        ["3.1.2	Delegatecall should not be used on untrusted contracts", ['controlled-delegatecall'] ],
        ["3.1.3	Invoke function with “this” keyword should be used with caution", ['this-usage', 'var-read-using-this'] ]]],

        [ "4. Testing Privilege Function",
        ["4.1	Privilege functions",
        ["4.1.1	State variables should not be unfairly controlled by privileged accounts", ['centralized-state'] ],
        ["4.1.2	Privileged functions or modifications of critical states should be logged", ['insufficient-logging'] ]]],

        [ "5. Testing Control Flow",
        ["5.1	Reentrancy",
        ["5.1.1	Reentrant calling should not negatively affect the contract states", ['reentrancy-eth', 'reentrancy-no-eth'] ]],
        ["5.2	Input validation",
        ["5.2.1	Lack of input validation", ['missing-zero-check'] ]]],

        [ "6. Testing Access Control",
        ["6.1	Contract's authentication",
        ["6.1.1	tx.origin should not be used for authentication", ['tx-origin'] ],
        ["6.1.2	Authentication measures must be able to correctly identify the user", [] ]],
        ["6.2	Contract's authorization",
        ["6.2.1	The roles are well defined and enforced", [] ],
        ["6.2.2	The roles can be safely transferred", [] ],
        ["6.2.3	Least privilege principle should be used for the rights of each role", [] ]],
        ["6.3	Signature verification",
        ["6.3.1	Signed signature should be used properly", [] ]],
        ["6.4	Access control on critical function",
        ["6.4.1	The critical function should enforce an access control", [] ]]],
        
        [ "7. Testing Randomness",
        ["7.1	External Source" ,
        ["7.1.1	VRF", [] ],
        ["7.1.2	Provenance hash", [] ]],
        ["7.2	Internal Source",
        ["7.2.1	Future block hash", [] ]]],

        [ "8. Testing Loop Operation",
        ["8.1	Block gas limit",
        ["8.1.1	Gas cost could exceed the block limit from loop operations", ['costly-loop'] ]],
        ["8.2	Reusing msg.value",
        ["8.2.1	Improper using msg.value in a loop", ['msg-value-loop'] ]],
        ["8.3	Unexpected revert inside loop",
        ["8.3.1	Using multiple external calls in a loop", ['loop-reverted', 'calls-loop'] ]],
        ["8.4	Using flow control expressions over loop execution",
        ["8.4.1	Control flow operator skips a crucial part of code", ['loop-skip'] ]],
        ["8.5	Inconsistent loop iterator",
        ["8.5.1	Having multiple expression that alter the same iterator of the loop", ['dirty-iterators'] ],
        ["8.5.2	Variable loop boundary", ['state-changing-loop'] ]]],
        
        [ "9. Testing Contract Upgradability",
        ["9.1	Identify an upgradability in contract",
        ["9.1.1	Identify a delegatecall instruction that could lead to the contract upgradability", ['controlled-delegatecall'] ],
        ["9.1.2	Identify a selfdestruct instruction that could lead to the contract upgradability", ['suicidal'] ],
        ["9.1.3	The initialize function implementation", [] ],
        ["9.1.4	The initialize function could only be executed once by the authorized party", [] ]],
        ["9.2	Upgradable proxy contract pitfalls",
        ["9.2.1	Storage slot allocation should not conflict", ['unsafe-initiate'] ]],
        ["9.3  Upgradable proxy contract pitfalls",
        ["9.3.1    Storage slot allocation should not conflict", []]]]
    ]

class InspexTestingGuideChecklist(AbstractPrinter):
    ARGUMENT = "inspex-checklist"
    HELP = "Print results of the detectors according to Inspex's Smart Contract Security Testing Guide."

    WIKI = "https://inspex.gitbook.io/testing-guide/"
    result = ''
    def filterDetector(self):
        filteredDetectors = STANDARD_ISSUES.copy()
        for i, issue in enumerate(STANDARD_ISSUES):
            tmp = []
            for d in self.slither.detectors:
                if d.ARGUMENT in issue[1]:
                    tmp.append(d)
                    # filteredDetectors.append([d, issue[0]])
            filteredDetectors[i].append(tmp)
        return filteredDetectors

    def createDetectorMapping(self):
        res = {}
        for d in self.slither.detectors:
            d.logger = None
            res[d.ARGUMENT] = d.detect()
        return res

    @staticmethod
    def formatIssue(_str: str) -> str:
        _str = _str.lstrip()
        return  re.sub(r'^- ?', '', _str)
    
    def addResult(self, line :str):
        self.result += line + '\n'
    
    def deliverResult(self, result):
        print(self.result)

    def output(self, _filename):
        oResult = self._output(_filename)
        self.deliverResult(oResult)
        return oResult
    
    def _output(self, _filename):
        res = ''
        total = 0
        detected = []
        detectorMap = self.createDetectorMapping()
        
        for standard in STANDARD_ISSUES:
            self.addResult(standard[0])
            count = 0
            for testing in standard[1:]:
                self.addResult(f'\t{testing[0]}')
                for issue in testing[1:]:
                    subHead = issue[0]
                    headFindings = []
                    for arg in issue[1]: # For each detecotr, which some dont have
                        iss = []
                        iss = detectorMap[arg]
                        for i in iss:
                            for l in i["description"].split('\n'):
                                if len(l) == 0: # blank lines
                                    continue
                                finding = self.formatIssue(l)
                                if '#' in finding:
                                    count += 1
                                    total += 1
                                    headFindings.append(f'- [ ] (IDX-{total}) {finding}') # Print each findings
                                    detected.append(f'- [ ] (IDX-{total}) {subHead} | {finding}')
                    if len(issue[1]) == 0: # Dont have any supported detector
                        subHead = f'❗️ {subHead}'
                        headFindings = ['- [ ] Checked ( There are no supported detectors at the moment. Please manually audit. )']
                        count += 1
                    elif len(headFindings) == 0:
                        subHead = f'✅ {subHead}'
                        headFindings = ['( No issue found )']
                    else:
                        subHead = f'🔎 {subHead}'
                    self.addResult(f'\t  {subHead}')
                    for f in headFindings:
                        self.addResult(f'\t{f}')
                    self.addResult('')
            self.addResult(f'There are {count} issue(s) need too be addressed')
            self.addResult('-'*3+'\n')

        self.addResult('##All detected issues\n')
        for i in detected:
            self.addResult(i)
        return self.generate_output("")
    
class InspexTestingGuideChecklistCSV(InspexTestingGuideChecklist):
    ARGUMENT = "inspex-checklist-csv"
    HELP = "Print results of the detectors according to Inspex's Smart Contract Security Testing Guide in CSV format."
    WIKI = "https://inspex.gitbook.io/testing-guide/"

    response = {
        '✅': 'No issues found',
        '🔎': 'Found some issues. Please look at the full result',
        '❗️': 'There are no supported detectors',
    }

    def addResult(self, line :str):
        if self.result == '': # add header
            self.result += 'Testing-ID,Title,Checked,Notes\n'
        line = line.lstrip()
        if re.match(r'^[1-9]\.\s+',line):
            self.result += re.sub(r'^[1-9]\.\s+','',line) + ',,,' + '\n'
        elif re.match(r'^[1-9]\.\d\s+',line):
            reg = re.match(r'^([1-9]\.\d)(\s+)(.+)',line)
            self.result += f'{reg[1]},{reg[3]},,\n'
        elif re.match(r'^(✅|🔎|❗️)\s+([1-9]\.\d\.\d{1,2})\s+(.+)',line):
            reg = re.match(r'^(✅|🔎|❗️)\s+([1-9]\.\d\.\d{1,2})\s+(.+)',line)
            self.result += f'{reg[2]},{reg[3]},{reg[1]},{self.response[reg[1]]}\n'
        elif re.match(r'^-\s\[\s\]\s\((IDX-\d+)\)\s(\d\.\d\.\d+)\s+(.+) \| (.+)',line):
            reg = re.match(r'^-\s\[\s\]\s\((IDX-\d+)\)\s(\d\.\d\.\d+)\s+(.+) \| (.+)',line)
            self.result += f'{reg[1]},{reg[2]+" "+reg[3]},"{reg[4]}",\n'
        elif re.match(r'^##All',line):
            self.result += f'\nID,Standard,Issue,Checked\n'

class InspexTestingGuideChecklistXLS(InspexTestingGuideChecklistCSV):
    ARGUMENT = "inspex-checklist-xls"
    HELP = "Print results of the detectors according to Inspex's Smart Contract Security Testing Guide in xls file."
    WIKI = "https://inspex.gitbook.io/testing-guide/"

    def deliverResult(self, result):
        workbook = xlsxwriter.Workbook("InspexChecklist.xlsx", {'in_memory': True})

        ws1 = workbook.add_worksheet("Checklist")
        # Set heading
        ws1.set_column_pixels(0,0,90)
        scaling = 0.73
        headFormat = workbook.add_format({'border_color': '#FF9900', 'bg_color':'#FF9900'})
        headBU = workbook.add_format({'bold': True, 'underline': True, 'border_color': '#FF9900', 'bg_color':'#FF9900'})
        headU = workbook.add_format({'underline': True, 'border_color': '#FF9900', 'bg_color':'#FF9900'})
        for i in range(4):
            ws1.write_column(0,i,[None,None,None,None,None], headFormat)
        ws1.insert_image(0,0,(Path(__file__).parent /  'inspex_logo.png').resolve(), {'object_position': 3, 'x_offset': 8, 'x_scale': scaling, 'y_scale': scaling})
        ws1.merge_range('B2:D2', 'Smart Contract Security Testing Guide Checklist', headBU)
        ws1.merge_range('B3:D3', 'A comprehensive outline for ensuring that smart contracts remain fortified against general exploits', headFormat)
        ws1.merge_range('B4:D4', 'https://docs.inspex.co/smart-contract-security-testing-guide/')
        ws1.write_url('B4', 'https://docs.inspex.co/smart-contract-security-testing-guide/')
        ws1.write_rich_string('B4', 'For in-depth detail: ', headU, 'https://docs.inspex.co/smart-contract-security-testing-guide/', headFormat)
        
        white = workbook.add_format({'border_color': 'white', 'bg_color':'white'})
        whiteB = workbook.add_format({'bold': True, 'border_color': 'white', 'bg_color':'white'})
        ws1.write_row(5,0,[None,None,None,None], white)
        
        # Set check list
        ws1.set_column_pixels(1,1,480)
        ws1.set_column_pixels(3,3,290)
        grayB = workbook.add_format({'bold': True, 'border_color': '#CCCCCC', 'bg_color':'#CCCCCC'})
        grayBU = workbook.add_format({'bold': True, 'underline': True, 'border_color': '#CCCCCC', 'bg_color':'#CCCCCC'})
        lines = self.result.split('\n')
        i = 0
        offset = 6
        while lines[i] != '':
            line = [ '{}'.format(x) for x in list(csv.reader([lines[i]], delimiter=',', quotechar='"'))[0] ]
            if line[1] == '':
                ws1.merge_range(offset+i,0,offset+i,3, line[0], grayB)
            elif re.match(r'^\d\.\d{1,2}$' ,line[0]):
                ws1.write_string(offset+i,0,line[0], grayB)
                ws1.write_row(offset+i,1,line[1:], grayBU)
            else:
                if line[1] == 'Title':
                    blankWhiteB = workbook.add_format({'bold': True, 'border_color': 'white', 'bg_color':'white'})
                    ws1.write_row(offset+i,0,line, blankWhiteB)
                else:
                    ws1.write_string(offset+i,0,line[0], whiteB)
                    ws1.write_row(offset+i,1,line[1:], white)
            i += 1

        ws2 = workbook.add_worksheet("Issues")
        ws2.set_column_pixels(0,0,50)
        ws2.set_column_pixels(1,1,250)
        ws2.set_column_pixels(2,2,400)
        bold = workbook.add_format({'bold': True})
        wrap = workbook.add_format({'text_wrap': True})
        i += 1
        sheet2Offset = i
        while i < len(lines)-1:
            line = [ '{}'.format(x) for x in list(csv.reader([lines[i]], delimiter=',', quotechar='"'))[0] ]
            print(line)
            if line[0] == 'ID':
                ws2.write_row(0,0, line, bold)
            else:
                ws2.write_row(i-sheet2Offset,0, line, wrap)
            i += 1
        workbook.close()
        print("The checklist file, 'InspexChecklist.xlsx', has been created.")