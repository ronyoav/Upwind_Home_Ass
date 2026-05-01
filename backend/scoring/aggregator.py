from backend.models.email_request import Signal

# Rule engine is dominant (70%) — deterministic and explainable.
# LLM features contribute 30% — extracted by LLM, scored by rules.
_RULE_WEIGHT = 0.70
_LLM_WEIGHT = 0.30


def aggregate(rule_score: int, llm_score: int, all_signals: list[Signal]) -> tuple[int, str, str]:
    """Returns (final_score, verdict, verdict_label)."""
    final = int(rule_score * _RULE_WEIGHT + llm_score * _LLM_WEIGHT)
    final = max(0, min(final, 100))

    if final <= 30:
        return final, "safe", "Safe"
    elif final <= 60:
        return final, "suspicious", "Suspicious"
    else:
        return final, "dangerous", "Likely Phishing"
