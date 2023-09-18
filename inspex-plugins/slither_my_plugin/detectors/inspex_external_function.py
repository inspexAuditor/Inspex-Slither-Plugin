from slither.detectors.functions.external_function import ExternalFunction
from slither_my_plugin.detectors.extends.summary_table import SummaryTable
from slither.detectors.abstract_detector import DetectorClassification

class InspexExternalFunction(ExternalFunction,  SummaryTable):
    ARGUMENT = "inspex-external-function"
    HELP = "Public function that could be declared external"
    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#public-function-that-could-be-declared-external"

    WIKI_TITLE = "Public function that could be declared external"
    WIKI_DESCRIPTION = "`public` functions that are never called by the contract should be declared `external` to save gas."
    WIKI_RECOMMENDATION = (
        "Use the `external` attribute for functions never called from the contract."
    )