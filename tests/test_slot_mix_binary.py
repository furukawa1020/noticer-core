from noticer_core.shared_slot_branch import crossed_public_futures
from noticer_core.shared_slot_causal import binary_minimax
from noticer_core.shared_slot_first import verify_public_futures
from noticer_core.shared_slot_game import PublicSlotGame
from noticer_core.slot_mix_contract import SlotMixGame
from noticer_core.slot_mix_solve import solve_mix


def test_binary_special_case_and_general_solver_agree():
    tapes = crossed_public_futures()
    binary = binary_minimax(verify_public_futures(*tapes))
    result = solve_mix(SlotMixGame(PublicSlotGame(tapes)))
    assert binary.deterministic == 0
    assert result.certificate is not None and result.certificate.value == binary.randomized
