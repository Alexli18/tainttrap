"""Regression gate over the detection benchmark (eval/detection): replayed attack calls stay
caught and benign twins are never blocked. The cases were written knowing the rules, so this
guards against regressions; it is not an independent measure of detection."""

import pytest
from eval.detection.__main__ import run, summarize


@pytest.mark.parametrize("mode", ["soft", "strict"])
def test_detection_benchmark(mode):
    s = summarize(run(None, mode))
    assert s["errors"] == 0
    assert s["attack_caught"]["rate"] == 1.0, s["misses"]
    assert s["benign_blocked"]["k"] == 0, s["false_alarms"]
