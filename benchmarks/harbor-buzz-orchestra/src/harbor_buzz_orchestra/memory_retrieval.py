"""Opt-in cold-memory regression adapted from block/buzz PR #6950.

Upstream head: 1a2833f45fb68021277070507965757337c810fd.
Uses this fork's existing DONE runtime instead of the newer native-task harness.
"""

import re

CONDITION = "memory-retrieval"
INSTRUCTION = (
    "How many total customers did we have in April 2024? "
    "Reply with DONE: followed only by the exact customer count."
)
# Harness-side only. Never upload this module or seed values into agent prompts.
SEEDS = {
    "total-customers-per-month": "Monthly average total customers: 361,250.",
    "customer-value-metric": "Last month's customers: 351,340. Revenue per customer: 2,400.",
    "customers-metrics-spring-24": (
        "March 2024 total customers: 325,401. "
        "April 2024 active customers named John: 3,710."
    ),
    "new-customers-april-2024": "April 2024 new customers: 21,604.",
    "total-customers-metric": "April 2024 total customers: 352,345.",
}


def score_answer(content: str) -> float:
    """Reject distractors, approximation, dumps, and unrelated numeric prose."""
    return float(re.fullmatch(r"DONE:\s*(?:352,345|352345)\s*", content) is not None)
