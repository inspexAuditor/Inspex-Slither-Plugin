from slither_my_plugin.detectors.insufficient_logging import InsufficientLogging
from slither_my_plugin.detectors.assert_statement import AssertStatement
from slither_my_plugin.detectors.floating_pragma_version import FloatingPragmaVersion
from slither_my_plugin.detectors.modifiable_ownership import ModifiableOwnership
from slither_my_plugin.detectors.assign_memory_array import AssignMemoryArray
from slither_my_plugin.detectors.invoke_unknown_external_functions import InvokeUnknownExternalFunctions
from slither_my_plugin.detectors.approve_unknown_address import ApproveUnknownAddress
from slither_my_plugin.detectors.state_changing_loop import StateChangingLoop
from slither_my_plugin.detectors.loop_reverted import LoopReverted
from slither_my_plugin.detectors.explicit_type_conversion import ExplicitTypeConversion
from slither_my_plugin.detectors.inexplicit_variable_visibility import InexplicitVariableVisibility
from slither_my_plugin.detectors.centralized_state import CentralizedState
from slither_my_plugin.detectors.strict_equalities import StrictEqualities
from slither_my_plugin.detectors.inspex_external_function import InspexExternalFunction
from slither_my_plugin.detectors.inspex_solc_version import InspexIncorrectSolc
from slither_my_plugin.detectors.this_usage import SelfInvocation
from slither_my_plugin.detectors.loop_skip import LoopSkip
from slither_my_plugin.detectors.dirty_iterators import DirtyIterators
from slither_my_plugin.detectors.unsafe_initiate import UnsafeInitiate
from slither_my_plugin.detectors.standard_token_check import StandardTokenCheck

from slither_my_plugin.printers.inspex_checklist import InspexTestingGuideChecklist, InspexTestingGuideChecklistCSV, InspexTestingGuideChecklistXLS

def make_plugin():
    plugin_detectors = [
        InsufficientLogging, 
        AssertStatement, 
        FloatingPragmaVersion, 
        ModifiableOwnership, 
        AssignMemoryArray, 
        InvokeUnknownExternalFunctions, 
        ApproveUnknownAddress, 
        StateChangingLoop, 
        LoopReverted, 
        ExplicitTypeConversion,
        CentralizedState,
        InexplicitVariableVisibility,
        StrictEqualities,
        InspexExternalFunction,
        InspexIncorrectSolc,
        SelfInvocation,
        LoopSkip,
        DirtyIterators,
        UnsafeInitiate,
        StandardTokenCheck
    ]

    plugin_printers = [
        InspexTestingGuideChecklist,
        InspexTestingGuideChecklistCSV,
        InspexTestingGuideChecklistXLS
    ]


    return plugin_detectors, plugin_printers