"""Local fixture/grader tests, not a model retrieval evaluation."""

from harbor_buzz_orchestra.memory_retrieval import INSTRUCTION, SEEDS, score_answer


def test_answer_is_only_in_one_cold_seed():
    assert "352345" not in INSTRUCTION.replace(",", "")
    assert sum("352,345" in value for value in SEEDS.values()) == 1
    assert "core" not in SEEDS
    assert all(slug not in INSTRUCTION for slug in SEEDS)


def test_grader_accepts_exact_count_only():
    assert score_answer("DONE: 352,345") == 1.0
    assert score_answer("DONE: 352345") == 1.0
    for answer in (
        "DONE: I could not find it",
        "DONE: 325,401",
        "DONE: about 352,345",
        "DONE: revenue was 352,345",
        "DONE: 352,345 or 361,250",
        "352,345",
    ):
        assert score_answer(answer) == 0.0


def test_task_instruction_and_base_prompt_do_not_leak_answer():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    instruction = (root / "tasks/memory-retrieval/instruction.md").read_text()
    prompt = (root.parents[1] / "crates/buzz-acp/src/base_prompt.md").read_text()
    assert instruction.strip() == INSTRUCTION
    assert "352345" not in prompt.replace(",", "")
    assert "buzz mem ls" in prompt
    assert "buzz mem get <slug>" in prompt
