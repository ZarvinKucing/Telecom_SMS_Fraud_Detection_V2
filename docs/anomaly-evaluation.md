# Isolation Forest: what was measured

**Setup.** Synthetic data only (there are no fraud labels in real data, so none of this says anything about real traffic).
Seeds 1-10, 7 days each, 99,299 sender-hour windows in total, 20 injected positive windows (a pumping sender and a
spiking sender per seed). Features: log volume, log distinct destinations, repeat ratio, delivery ratio, hour (sin/cos).
Model fitted on the same batch it scores. Command: `evaluate_anomaly(range(1, 11), AnomalyConfig(percentile_threshold=...))`.

| Flag windows at or above | Flagged | True positives | Recall | Precision |
|---|---|---|---|---|
| 99.0th percentile | 999 | 11 | 0.55 | 0.011 |
| 99.5th percentile (default) | 502 | 10 | 0.50 | 0.020 |
| 99.9th percentile | 102 | 7 | 0.35 | 0.069 |

**Reading.** As a standalone detector it is weak: about half the injected windows are found, at the cost of roughly 50
false flags for every true one. On seed 1 it would raise 52 alerts where the rules raise 3. The injected windows rank
high (about the 98.8th and 99.8th percentile) but not at the top, because the model scores rarity against the whole
population, and a busy-but-normal sender's ordinary hours also look rare. Deviation from a sender's *own* history is the
spiking-sender rule's job, not this model's.

**Consequence in the code.** `AnomalyConfig.corroborate_only` defaults to `True`: the model can only raise the score of an
entity that a rule already flagged (spiking sender: 50.0 to 64.99 on seed 1) and cannot create alerts alone. A clean run
still produces 0 alerts. Turning it off is possible but not recommended.

**Tried and reverted.** Shrinking the delivery ratio of tiny windows toward the global mean (to cut small-sample noise)
changed recall from 0.55 to 0.60 at the 99th percentile, 0.50 to 0.50 at the 99.5th, and 0.35 to 0.00 at the 99.9th. That
is noise at n=20, so the extra code was removed.

**Not done.** No tuning on real data, no comparison with other detectors, no confidence intervals. Twenty positives is
too few to rank configurations.
