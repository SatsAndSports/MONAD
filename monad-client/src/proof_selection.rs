//! Pure, side-effect-free selection of Cashu proofs for a target post-swap value.
//!
//! This module is intentionally independent of SQLite, channel logic, and wallet
//! state. It operates only on a caller-provided list of proof candidates.
//!
//! # Selection heuristic
//!
//! Cashu input fees are charged per proof (`input_fee_ppk`), so reducing the
//! number of selected proofs indirectly reduces fees. This selector therefore
//! sorts candidates largest-first (lower fee as a tie-breaker) and greedily
//! includes them until the post-swap target is reached. An overshooting
//! candidate is skipped only when the remaining smaller candidates can still
//! satisfy the target, avoiding unnecessary overspend.
//!
//! This is *not* a strict fee-minimizing knapsack solver. It assumes that large
//! and small proofs carry similar `input_fee_ppk` values on average, so
//! preferring fewer, larger proofs is a reasonable proxy for lower total fees
//! while keeping the algorithm simple and fast.

use std::fmt;

pub const MAX_SELECTED_INPUT_PROOFS: usize = 992;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallestFirstProofCandidate {
    pub proof_id: String,
    pub keyset_id: String,
    pub amount_raw: u64,
    pub input_fee_ppk: Option<u64>,
}

/// A single available proof that may be selected to fund a target value.
///
/// `amount_raw` is the face value in the mint's raw units (e.g. satoshis). The
/// `input_fee_ppk` is the per-proof fee expressed in parts-per-thousand of the
/// unit and is combined with other selected proofs using
/// `ceil(sum(input_fee_ppk) / 1000)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofCandidate {
    pub proof_id: String,
    pub amount_raw: u64,
    pub input_fee_ppk: u64,
}

/// The result of selecting proofs for a target post-swap value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSelection {
    pub proof_ids: Vec<String>,
    pub input_value_raw: u64,
    pub input_fee_raw: u64,
    pub post_swap_value_raw: u64,
}

/// Errors returned by [`select_mixed_fee_inputs_for_post_swap_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofSelectionError {
    /// Not enough post-swap value is available across all candidates.
    Insufficient {
        target_post_swap_raw: u64,
        available_post_swap_raw: u64,
    },
    InputKeysetMetadataUnavailable {
        keyset_ids: Vec<String>,
    },
    TooManyInputProofs {
        selected: usize,
        maximum: usize,
    },
    /// An internal total overflowed during selection.
    Overflow,
}

impl fmt::Display for ProofSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insufficient {
                target_post_swap_raw,
                available_post_swap_raw,
            } => write!(
                f,
                "insufficient proofs: target_post_swap_raw={target_post_swap_raw} available_post_swap_raw={available_post_swap_raw}"
            ),
            Self::InputKeysetMetadataUnavailable { keyset_ids } => write!(
                f,
                "input keyset metadata unavailable for: {}",
                keyset_ids.join(", ")
            ),
            Self::TooManyInputProofs { selected, maximum } => write!(
                f,
                "too many input proofs: selected={selected} maximum={maximum}"
            ),
            Self::Overflow => write!(f, "proof selection total overflow"),
        }
    }
}

/// Select strict smallest-first inputs until their value after input fees covers
/// `target_post_swap_raw`. Unknown metadata is an error only when encountered
/// before the target is reached; later proofs are irrelevant to this policy.
pub fn select_smallest_first_inputs_for_funding_target(
    mut candidates: Vec<SmallestFirstProofCandidate>,
    target_post_swap_raw: u64,
) -> Result<ProofSelection, ProofSelectionError> {
    candidates.sort_by(|a, b| {
        a.amount_raw
            .cmp(&b.amount_raw)
            .then(a.proof_id.cmp(&b.proof_id))
    });
    let mut selected = ProofTotals::ZERO;
    let mut proof_ids = Vec::new();

    for candidate in candidates {
        if selected.post_swap_value() >= target_post_swap_raw {
            break;
        }
        let Some(input_fee_ppk) = candidate.input_fee_ppk else {
            return Err(ProofSelectionError::InputKeysetMetadataUnavailable {
                keyset_ids: vec![candidate.keyset_id],
            });
        };
        selected = selected.checked_add(ProofTotals {
            amount_raw: candidate.amount_raw,
            fee_ppk_sum: input_fee_ppk,
        })?;
        proof_ids.push(candidate.proof_id);
        if proof_ids.len() > MAX_SELECTED_INPUT_PROOFS {
            return Err(ProofSelectionError::TooManyInputProofs {
                selected: proof_ids.len(),
                maximum: MAX_SELECTED_INPUT_PROOFS,
            });
        }
    }

    let post_swap_value_raw = selected.post_swap_value();
    if post_swap_value_raw < target_post_swap_raw {
        return Err(ProofSelectionError::Insufficient {
            target_post_swap_raw,
            available_post_swap_raw: post_swap_value_raw,
        });
    }
    Ok(ProofSelection {
        proof_ids,
        input_value_raw: selected.amount_raw,
        input_fee_raw: selected.input_fee_raw(),
        post_swap_value_raw,
    })
}

impl std::error::Error for ProofSelectionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProofTotals {
    amount_raw: u64,
    fee_ppk_sum: u64,
}

impl ProofTotals {
    const ZERO: Self = Self {
        amount_raw: 0,
        fee_ppk_sum: 0,
    };

    fn checked_add(self, other: Self) -> Result<Self, ProofSelectionError> {
        Ok(Self {
            amount_raw: self
                .amount_raw
                .checked_add(other.amount_raw)
                .ok_or(ProofSelectionError::Overflow)?,
            fee_ppk_sum: self
                .fee_ppk_sum
                .checked_add(other.fee_ppk_sum)
                .ok_or(ProofSelectionError::Overflow)?,
        })
    }

    fn checked_add_candidate(
        self,
        candidate: &ProofCandidate,
    ) -> Result<Self, ProofSelectionError> {
        self.checked_add(Self {
            amount_raw: candidate.amount_raw,
            fee_ppk_sum: candidate.input_fee_ppk,
        })
    }

    fn input_fee_raw(self) -> u64 {
        input_fee_raw_from_ppk_sum(self.fee_ppk_sum)
    }

    fn post_swap_value(self) -> u64 {
        self.amount_raw.saturating_sub(self.input_fee_raw())
    }
}

/// Select proofs whose post-swap value is at least `target_post_swap_raw`.
///
/// Proofs are sorted largest-first, with lower `input_fee_ppk` breaking ties to
/// keep the resulting proof count low. A proof is skipped only when including
/// it would overshoot the target and the remaining smaller proofs can still
/// satisfy the target without it.
///
/// Returns [`ProofSelectionError::Insufficient`] when all candidates combined do
/// not provide enough post-swap value. Returns [`ProofSelectionError::Overflow`]
/// if any internal total would exceed `u64`.
///
/// A target of zero yields an empty selection.
pub fn select_mixed_fee_inputs_for_post_swap_target(
    mut candidates: Vec<ProofCandidate>,
    target_post_swap_raw: u64,
) -> Result<ProofSelection, ProofSelectionError> {
    if target_post_swap_raw == 0 {
        return Ok(ProofSelection {
            proof_ids: Vec::new(),
            input_value_raw: 0,
            input_fee_raw: 0,
            post_swap_value_raw: 0,
        });
    }

    candidates.retain(|candidate| {
        candidate.amount_raw > input_fee_raw_from_ppk_sum(candidate.input_fee_ppk)
    });
    candidates.sort_by(|a, b| {
        b.amount_raw
            .cmp(&a.amount_raw)
            .then(a.input_fee_ppk.cmp(&b.input_fee_ppk))
            .then(a.proof_id.cmp(&b.proof_id))
    });

    let suffix = compute_suffix_totals(&candidates)?;
    let mut selected = ProofTotals::ZERO;
    let mut proof_ids = Vec::new();

    for (i, candidate) in candidates.iter().enumerate() {
        if selected.post_swap_value() >= target_post_swap_raw {
            break;
        }

        let with_current = selected.checked_add_candidate(candidate)?;
        if with_current.post_swap_value() <= target_post_swap_raw {
            selected = with_current;
            proof_ids.push(candidate.proof_id.clone());
            continue;
        }

        let remaining_without_current = selected.checked_add(suffix[i + 1])?;
        if remaining_without_current.post_swap_value() >= target_post_swap_raw {
            continue;
        }

        selected = with_current;
        proof_ids.push(candidate.proof_id.clone());
    }

    let post_swap_value_raw = selected.post_swap_value();
    if post_swap_value_raw < target_post_swap_raw {
        return Err(ProofSelectionError::Insufficient {
            target_post_swap_raw,
            available_post_swap_raw: suffix[0].post_swap_value(),
        });
    }
    if proof_ids.len() > MAX_SELECTED_INPUT_PROOFS {
        return Err(ProofSelectionError::TooManyInputProofs {
            selected: proof_ids.len(),
            maximum: MAX_SELECTED_INPUT_PROOFS,
        });
    }

    Ok(ProofSelection {
        proof_ids,
        input_value_raw: selected.amount_raw,
        input_fee_raw: selected.input_fee_raw(),
        post_swap_value_raw,
    })
}

/// Compute post-swap totals for every suffix of `candidates`.
///
/// The returned vector has length `candidates.len() + 1`, where index `i`
/// contains the totals of `candidates[i..]` and the final index is zero.
/// This lets the selector evaluate, in constant time, whether the remaining
/// proofs after the current candidate can still satisfy the target.
fn compute_suffix_totals(
    candidates: &[ProofCandidate],
) -> Result<Vec<ProofTotals>, ProofSelectionError> {
    let mut suffix = vec![ProofTotals::ZERO; candidates.len() + 1];

    for i in (0..candidates.len()).rev() {
        suffix[i] = suffix[i + 1].checked_add_candidate(&candidates[i])?;
    }

    Ok(suffix)
}

/// Convert a sum of per-proof `input_fee_ppk` values into the raw unit fee.
///
/// Cashu NUT-02 defines the total input fee as
/// `ceil(sum(input_fee_ppk) / 1000)`.
pub(crate) fn input_fee_raw_from_ppk_sum(fee_ppk_sum: u64) -> u64 {
    fee_ppk_sum.div_ceil(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, amount_raw: u64, input_fee_ppk: u64) -> ProofCandidate {
        ProofCandidate {
            proof_id: id.to_string(),
            amount_raw,
            input_fee_ppk,
        }
    }

    fn smallest_candidate(
        id: &str,
        keyset_id: &str,
        amount_raw: u64,
        input_fee_ppk: Option<u64>,
    ) -> SmallestFirstProofCandidate {
        SmallestFirstProofCandidate {
            proof_id: id.to_string(),
            keyset_id: keyset_id.to_string(),
            amount_raw,
            input_fee_ppk,
        }
    }

    #[test]
    fn smallest_first_is_deterministic_and_input_fees_are_additional() {
        let selection = select_smallest_first_inputs_for_funding_target(
            vec![
                smallest_candidate("b", "known", 5, Some(500)),
                smallest_candidate("c", "known", 1, Some(0)),
                smallest_candidate("a", "known", 5, Some(500)),
            ],
            10,
        )
        .unwrap();
        assert_eq!(selection.proof_ids, vec!["c", "a", "b"]);
        assert_eq!(selection.input_value_raw, 11);
        assert_eq!(selection.input_fee_raw, 1);
        assert_eq!(selection.post_swap_value_raw, 10);
    }

    #[test]
    fn smallest_first_does_not_skip_unknown_metadata_before_target() {
        let error = select_smallest_first_inputs_for_funding_target(
            vec![
                smallest_candidate("first", "missing", 1, None),
                smallest_candidate("enough", "known", 10, Some(0)),
            ],
            10,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProofSelectionError::InputKeysetMetadataUnavailable {
                keyset_ids: vec!["missing".to_string()]
            }
        );
    }

    #[test]
    fn smallest_first_ignores_unknown_metadata_after_target() {
        let selection = select_smallest_first_inputs_for_funding_target(
            vec![
                smallest_candidate("enough", "known", 10, Some(0)),
                smallest_candidate("later", "missing", 20, None),
            ],
            10,
        )
        .unwrap();
        assert_eq!(selection.proof_ids, vec!["enough"]);
    }

    #[test]
    fn smallest_first_enforces_portable_proof_limit() {
        let candidates = (0..=MAX_SELECTED_INPUT_PROOFS)
            .map(|i| smallest_candidate(&format!("{i:04}"), "known", 1, Some(0)))
            .collect();
        assert_eq!(
            select_smallest_first_inputs_for_funding_target(
                candidates,
                MAX_SELECTED_INPUT_PROOFS as u64 + 1
            ),
            Err(ProofSelectionError::TooManyInputProofs {
                selected: MAX_SELECTED_INPUT_PROOFS + 1,
                maximum: MAX_SELECTED_INPUT_PROOFS,
            })
        );
    }

    #[test]
    fn smallest_first_accepts_992_proofs() {
        let candidates = (0..MAX_SELECTED_INPUT_PROOFS)
            .map(|i| smallest_candidate(&format!("{i:04}"), "known", 1, Some(0)))
            .collect();
        let selection = select_smallest_first_inputs_for_funding_target(
            candidates,
            MAX_SELECTED_INPUT_PROOFS as u64,
        )
        .unwrap();
        assert_eq!(selection.proof_ids.len(), MAX_SELECTED_INPUT_PROOFS);
    }

    #[test]
    fn suffix_totals_empty() {
        let suffix = compute_suffix_totals(&[]).unwrap();

        assert_eq!(suffix, vec![ProofTotals::ZERO]);
    }

    #[test]
    fn suffix_totals_single_candidate() {
        let candidates = vec![candidate("proof-a", 10, 400)];
        let suffix = compute_suffix_totals(&candidates).unwrap();

        assert_eq!(
            suffix,
            vec![
                ProofTotals {
                    amount_raw: 10,
                    fee_ppk_sum: 400
                },
                ProofTotals::ZERO,
            ]
        );
    }

    #[test]
    fn suffix_totals_multiple_candidates() {
        let candidates = vec![
            candidate("proof-a", 10, 400),
            candidate("proof-b", 5, 1),
            candidate("proof-c", 2, 900),
        ];
        let suffix = compute_suffix_totals(&candidates).unwrap();

        assert_eq!(
            suffix,
            vec![
                ProofTotals {
                    amount_raw: 17,
                    fee_ppk_sum: 1301
                },
                ProofTotals {
                    amount_raw: 7,
                    fee_ppk_sum: 901
                },
                ProofTotals {
                    amount_raw: 2,
                    fee_ppk_sum: 900
                },
                ProofTotals::ZERO,
            ]
        );
        assert_eq!(suffix[0].post_swap_value(), 15);
        assert_eq!(suffix[1].post_swap_value(), 6);
        assert_eq!(suffix[2].post_swap_value(), 1);
    }

    #[test]
    fn suffix_totals_amount_overflow() {
        let candidates = vec![
            candidate("proof-a", u64::MAX, 0),
            candidate("proof-b", 1, 0),
        ];

        assert_eq!(
            compute_suffix_totals(&candidates),
            Err(ProofSelectionError::Overflow)
        );
    }

    #[test]
    fn suffix_totals_fee_overflow() {
        let candidates = vec![
            candidate("proof-a", 1, u64::MAX),
            candidate("proof-b", 1, 1),
        ];

        assert_eq!(
            compute_suffix_totals(&candidates),
            Err(ProofSelectionError::Overflow)
        );
    }

    #[test]
    fn post_swap_value_uses_ceiling_ppk_fee() {
        assert_eq!(ProofTotals::ZERO.post_swap_value(), 0);
        assert_eq!(
            ProofTotals {
                amount_raw: 17,
                fee_ppk_sum: 1000
            }
            .post_swap_value(),
            16
        );
        assert_eq!(
            ProofTotals {
                amount_raw: 17,
                fee_ppk_sum: 1001
            }
            .post_swap_value(),
            15
        );
    }

    #[test]
    fn selects_empty_for_zero_target() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-a", u64::MAX, 0),
                candidate("proof-b", 1, 0),
            ],
            0,
        )
        .unwrap();

        assert_eq!(
            selection,
            ProofSelection {
                proof_ids: Vec::new(),
                input_value_raw: 0,
                input_fee_raw: 0,
                post_swap_value_raw: 0,
            }
        );
    }

    #[test]
    fn sorts_larger_amount_then_lower_fee_then_id() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-d", 5, 0),
                candidate("proof-c", 10, 600),
                candidate("proof-b", 10, 100),
                candidate("proof-a", 10, 100),
            ],
            34,
        )
        .unwrap();

        assert_eq!(
            selection.proof_ids,
            vec!["proof-a", "proof-b", "proof-c", "proof-d"]
        );
        assert_eq!(selection.input_value_raw, 35);
        assert_eq!(selection.input_fee_raw, 1);
        assert_eq!(selection.post_swap_value_raw, 34);
    }

    #[test]
    fn includes_non_overshooting_candidate_even_when_suffix_can_satisfy() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-six", 6, 0),
                candidate("proof-five-a", 5, 0),
                candidate("proof-five-b", 5, 0),
            ],
            10,
        )
        .unwrap();

        assert_eq!(selection.proof_ids, vec!["proof-six", "proof-five-b"]);
        assert_eq!(selection.post_swap_value_raw, 11);
    }

    #[test]
    fn skips_oversized_candidate_when_suffix_can_satisfy_target() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-hundred", 100, 0),
                candidate("proof-eight", 8, 0),
                candidate("proof-two", 2, 0),
            ],
            10,
        )
        .unwrap();

        assert_eq!(selection.proof_ids, vec!["proof-eight", "proof-two"]);
        assert_eq!(selection.post_swap_value_raw, 10);
    }

    #[test]
    fn keeps_oversized_candidate_when_suffix_cannot_satisfy_target() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-hundred", 100, 0),
                candidate("proof-eight", 8, 0),
                candidate("proof-one", 1, 0),
            ],
            10,
        )
        .unwrap();

        assert_eq!(selection.proof_ids, vec!["proof-hundred"]);
        assert_eq!(selection.post_swap_value_raw, 100);
    }

    #[test]
    fn skip_decision_is_fee_aware() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-eleven", 11, 0),
                candidate("proof-ten", 10, 999),
            ],
            10,
        )
        .unwrap();

        assert_eq!(selection.proof_ids, vec!["proof-eleven"]);
        assert_eq!(selection.post_swap_value_raw, 11);
    }

    #[test]
    fn selects_additional_candidate_when_fees_make_raw_sum_insufficient() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-ten", 10, 999),
                candidate("proof-one", 1, 0),
            ],
            10,
        )
        .unwrap();

        assert_eq!(selection.proof_ids, vec!["proof-ten", "proof-one"]);
        assert_eq!(selection.input_value_raw, 11);
        assert_eq!(selection.input_fee_raw, 1);
        assert_eq!(selection.post_swap_value_raw, 10);
    }

    #[test]
    fn returns_insufficient_with_available_post_swap() {
        let error = select_mixed_fee_inputs_for_post_swap_target(
            vec![
                candidate("proof-five", 5, 0),
                candidate("proof-four", 4, 999),
            ],
            10,
        )
        .unwrap_err();

        assert_eq!(
            error,
            ProofSelectionError::Insufficient {
                target_post_swap_raw: 10,
                available_post_swap_raw: 8,
            }
        );
    }

    #[test]
    fn exact_capacity_excludes_non_contributing_proofs() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![candidate("toxic", 100, 100_000), candidate("good", 10, 0)],
            10,
        )
        .unwrap();
        assert_eq!(selection.proof_ids, vec!["good"]);
    }

    #[test]
    fn exact_capacity_uses_ceil_fee_when_filtering_non_contributing_proofs() {
        let selection = select_mixed_fee_inputs_for_post_swap_target(
            vec![candidate("toxic", 2, 1001), candidate("good", 2, 0)],
            2,
        )
        .unwrap();
        assert_eq!(selection.proof_ids, vec!["good"]);
    }
}
