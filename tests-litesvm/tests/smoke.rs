mod common;
use common::*;

#[test]
fn smoke_v1_and_v2_load_init_call() {
    for mut env in [Env::v2(), Env::v1()] {
        let lp = seeded_keypair(1);
        let ctx = env.new_ctx(&lp, &init_params(0));
        let (r, m) = env.call(&lp, &ctx, &Call::new(1, 1_000_000, 100)).unwrap();
        println!("{r:?} cu={}", m.compute_units_consumed);
        assert_eq!(r.exec_size, 100);
        assert_eq!(r.exec_price_e6, ask(1_000_000, 30));
    }
}
