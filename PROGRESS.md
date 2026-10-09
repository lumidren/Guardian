# GUARDIAN Project Progress Tracker

## Phase 3: Evaluation Validity, Realism, External Validation and Release
- [x] P3-0. Freeze and reproduce (tag phase2-final, snapshot baseline, AUDIT.md G1-G10, ADR-019)
- [x] P3-1. Leakage and label audit (tests first, artifact audit, shuffled labels, controls, LEAKAGE_AUDIT.md)
- [x] P3-2. Simulator realism v2 (tiers, true mimicry, low-and-slow, hard negatives, SIMULATOR_REALISM.md)
- [x] P3-3. Evaluation v2: correct metrics and sample sizes (one metrics module, episode-level, 5 seeds, CIs)
- [x] P3-4. Fair baselines and rigorous ablations (equal budget, one-class SVM/LOF, full test set ablations)
- [x] P3-5. External dataset validation (public IoT dataset, feature mapping, EXTERNAL_DATA.md)
- [x] P3-6. Real load, performance and enforcement tests (real-time replay load test, drop counters, real nftables)
- [x] P3-7. Plausibility guard and CI enforcement (eval/guard.py, CI smoke with guards and controls)
- [x] P3-8. Real-device readiness (results/real/, REAL_DATA_VALIDATION.md, capture and import tools)
- [x] P3-9. Security and robustness of GUARDIAN itself (THREAT_MODEL.md, fuzz tests, baseline poisoning)
- [ ] P3-10. Paper, documentation and release (IEEE_PAPER_DRAFT.md, README rewrite, v1.0 tag, demo)

---

## Phase 2: Evaluation Integrity, Hardening and Completion (COMPLETED)
- [x] P2-0. Freeze and audit (tag phase1-final, snapshot baseline, AUDIT.md, PHASE1_GAP_CHECK.md)
- [x] P2-1. Repository hygiene (unified src/guardian layout, pinned dependencies, Python 3.11)
- [x] P2-2. Evaluation framework core (new package: eval/, seeded 14-day stream, real pipeline)
- [x] P2-3. Model training and caching (content-hash bundle cache, exception on missing model)
- [x] P2-4. Real baselines and ablations (static rules, pooled IF, z-score only, layer ablations)
- [x] P2-5. Adversarial and sensitivity testing (evasion modes, operating curve, threats to validity)
- [x] P2-6. Real system measurements (psutil CPU/RAM, 3 distinct latencies, scalability test)
- [x] P2-7. Close the Phase 1 gaps (close items from PHASE1_GAP_CHECK.md)
- [x] P2-8. Honest reporting (reproducible tables/LaTeX, honest README, IEEE paper draft)
- [x] P2-9. CI guardrails and final acceptance (no-hardcoded-metrics test, smoke eval in CI)

---

## Current Status
- **Active Milestone**: P3-10 (Paper, documentation, v1.0 release)
- **Completed Milestones**: P3-0, P3-1, P3-2, P3-3, P3-4, P3-5, P3-6, P3-7, P3-8, P3-9, P2-0 to P2-9, M0-M14
- **Phase 3 Findings**: G1, G2, G3, G4, G5, G6, G7, G8, G9, G10 ALL RESOLVED (10/10).
- **Quality Gates**: Ruff clean, Mypy strict clean, 142 unit tests passing, controls battery active, plausibility guard active.
