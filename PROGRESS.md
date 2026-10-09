# GUARDIAN Project Progress Tracker

## Phase 2: Evaluation Integrity, Hardening and Completion
- [x] P2-0. Freeze and audit (tag `phase1-final`, snapshot baseline, AUDIT.md, PHASE1_GAP_CHECK.md)
- [x] P2-1. Repository hygiene (unified `src/guardian` layout, pinned dependencies, Python 3.11)
- [x] P2-2. Evaluation framework core (new package: `eval/`, seeded 14-day stream, real pipeline)
- [x] P2-3. Model training and caching (content-hash bundle cache, exception on missing model)
- [ ] P2-4. Real baselines and ablations (static rules, pooled IF, z-score only, layer ablations)
- [ ] P2-5. Adversarial and sensitivity testing (evasion modes, operating curve, threats to validity)
- [ ] P2-6. Real system measurements (psutil CPU/RAM, 3 distinct latencies, scalability test)
- [ ] P2-7. Close the Phase 1 gaps (close items from PHASE1_GAP_CHECK.md)
- [ ] P2-8. Honest reporting (reproducible tables/LaTeX, honest README, IEEE paper draft)
- [ ] P2-9. CI guardrails and final acceptance (no-hardcoded-metrics test, smoke eval in CI)

---

## Phase 1 Milestones (docs/AGENT_PLAN.md)
- [x] M0 scaffolding and quality gates
- [x] M1 contracts and DB
- [ ] M2 simulator (feeds P2-7)
- [ ] M3 sources and windows (feeds P2-7)
- [ ] M4 features (feeds P2-7)
- [ ] M5 profiles and stages (feeds P2-7)
- [ ] M6 detectors (feeds P2-7)
- [ ] M7 network identity and fusion (feeds P2-7)
- [ ] M8 explainability (feeds P2-7)
- [ ] M9 response (feeds P2-7)
- [ ] M10 pipeline, drift, feedback (feeds P2-7)
- [ ] M11 API (feeds P2-7)
- [ ] M12 dashboard (feeds P2-7)
- [ ] M13 evaluation and enhancements (superseded by P2-2 to P2-6)
- [ ] M14 hardening and docs (feeds P2-8)

---

## Current Status
- **Active Milestone**: P2-4 (Real baselines and ablations)
- **Completed Milestones**: P2-0, P2-1, P2-2, P2-3, M0, M1
- **Next Milestone**: P2-4 (Real baselines and ablations)
- **Known Gaps**: See `docs/AUDIT.md` (F1–F4, F12) and `docs/PHASE1_GAP_CHECK.md` (M2–M14).


