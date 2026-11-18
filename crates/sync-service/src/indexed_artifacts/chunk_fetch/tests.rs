use super::*;

#[test]
fn chunk_byte_budget_releases_hedge_charge_on_drop() {
    let budget = ChunkByteBudget::new(10);
    assert!(budget.try_charge(6));
    assert!(budget.try_charge_hedge(5).is_none());
    let hedge = budget.try_charge_hedge(4).expect("hedge fits the budget");
    assert!(!budget.try_charge(1));

    drop(hedge);
    assert_eq!(budget.in_flight_bytes(), 6);
    budget.release(6);
    assert_eq!(budget.in_flight_bytes(), 0);
    assert_eq!(budget.max_observed_in_flight_bytes(), 10);
}
