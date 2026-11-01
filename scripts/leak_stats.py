"""The permutation test the leak-class scripts share.

A discriminator is a value that is high for the class it is supposed to
detect and low for the others.  Whether the observed separation is
evidence or an artefact of a small sample is decided by permuting the
labels: if the observed separation is no better than what the labels
would produce at random, it is not a discriminator.
"""

from __future__ import annotations

import random

SEED = 20240117


def auc(positives, negatives):
    """The probability that a random positive outranks a random negative."""
    if not positives or not negatives:
        return 0.5
    wins = 0.0
    for p in positives:
        for n in negatives:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def permutation_p(positives, negatives, seed=SEED, trials=5000):
    """The permutation p-value of the observed separation."""
    if not positives or not negatives:
        return {"auc": 0.5, "p_value": 1.0, "significant_at_0.05": False,
                "n_trials": trials}
    observed = auc(positives, negatives)
    pool = list(positives) + list(negatives)
    n_pos = len(positives)
    rng = random.Random(seed)
    count = 0
    for _ in range(trials):
        rng.shuffle(pool)
        a = auc(pool[:n_pos], pool[n_pos:])
        if abs(a - 0.5) >= abs(observed - 0.5):
            count += 1
    return {
        "auc": round(observed, 4),
        "p_value": round(count / trials, 4),
        "significant_at_0.05": (count / trials) < 0.05,
        "n_trials": trials,
    }
