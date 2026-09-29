//! Item 8: tag 5 (configure) authentication and validation, both auth modes.
mod common;
use common::*;
use percolator_match::v2::V2Config;
use percolator_match::vamm::{self, InitParams, MatcherCtx, OwnerProof};
use percolator_match::{CTX_BACKING_FEE_CAP_OFFSET, CTX_VAMM_OFFSET, MATCHER_CONTEXT_LEN};
use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

fn cap_bytes(d: &[u8]) -> u16 {
    u16::from_le_bytes(
        d[CTX_BACKING_FEE_CAP_OFFSET..CTX_BACKING_FEE_CAP_OFFSET + 2]
            .try_into()
            .unwrap(),
    )
}

// -----------------------------------------------------------------------------
// lp_pda mode (auth_mode 0)
// -----------------------------------------------------------------------------

#[test]
fn tag5_lp_pda_mode_correct_signer_sets_cap_and_call_carries_it() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    assert_eq!(cap_bytes(&env.ctx_data(&ctx)), 0);
    env.configure_lp_pda(&lp, &ctx, &op_cap(777)).unwrap();
    assert_eq!(cap_bytes(&env.ctx_data(&ctx)), 777);
    let (r, _) = env.call(&lp, &ctx, &Call::new(1, 1_000_000, 10)).unwrap();
    assert_eq!(r.backing_fee_cap_bps(), 777, "flags bits 8..21 carry the cap");
    assert_eq!((r.flags >> 8) & 0x3fff, 777);
    // batch legs carry it too
    let (rets, _) = env
        .batch(&lp, &ctx, &Batch::legacy(2, vec![Leg::new(0, 1_000_000, 5); 3]))
        .unwrap();
    assert!(rets.iter().all(|r| r.backing_fee_cap_bps() == 777));
    // boundary 10_000 accepted
    env.configure_lp_pda(&lp, &ctx, &op_cap(10_000)).unwrap();
    let (r, _) = env.call(&lp, &ctx, &Call::new(3, 1_000_000, 10)).unwrap();
    assert_eq!(r.backing_fee_cap_bps(), 10_000);
}

/// NEGATIVE CONTROLS: a different signer, or the right key unsigned.
#[test]
fn neg_tag5_lp_pda_mode_wrong_signer_or_unsigned() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    let before = env.ctx_data(&ctx);
    let other = seeded_keypair(2);
    let e = expect_err(env.configure_lp_pda(&other, &ctx, &op_cap(777)));
    assert_eq!(e, InstructionError::InvalidAccountData);
    let e = expect_err(env.send(&lp, false, &ctx, vamm::encode_configure(None, &op_cap(777))));
    assert_eq!(e, InstructionError::MissingRequiredSignature);
    assert_eq!(env.ctx_data(&ctx), before);
}

#[test]
fn tag5_cap_over_max_rejected_ctx_unchanged() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    let before = env.ctx_data(&ctx);
    for cap in [10_001u16, 16_383, u16::MAX] {
        let e = expect_err(env.configure_lp_pda(&lp, &ctx, &op_cap(cap)));
        assert_eq!(e, InstructionError::InvalidInstructionData, "cap {cap}");
    }
    assert_eq!(env.ctx_data(&ctx), before);
    // malformed op payloads
    for bad in [vec![0u8], vec![0u8, 1], vec![0u8, 1, 0, 0], vec![9u8, 0, 0], vec![]] {
        let e = expect_err(env.configure_lp_pda(&lp, &ctx, &bad));
        assert_eq!(e, InstructionError::InvalidInstructionData, "payload {bad:?}");
    }
    let e = expect_err(env.send(&lp, true, &ctx, vec![5, 2, 0, 1, 0]));
    assert_eq!(e, InstructionError::InvalidInstructionData, "auth_mode 2");
    assert_eq!(env.ctx_data(&ctx), before);
}

fn kind2_core() -> InitParams {
    InitParams {
        kind: 2,
        skew_spread_mult_bps: 100,
        ..init_params(0)
    }
}

fn valid_k2_cfg() -> V2Config {
    V2Config {
        thin_rebate_mult_bps: 50,
        skew_cap_bps: 300,
        rebate_cap_bps: 150,
        skew_ref_inventory: 1_000,
        ..fixed_fee_v2(20)
    }
}

#[test]
fn tag5_set_params_invalid_rejected_ctx_unchanged_valid_accepted() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(2));
    env.warp(10);
    env.call(&lp, &ctx, &Call::new(1, 1_000_000, 50)).unwrap(); // some state
    let before = env.ctx_data(&ctx);

    let mut bad: Vec<(&str, vamm::SetParams)> = vec![];
    let mut c = valid_k2_cfg();
    c.fee_lo_bps = 30;
    c.fee_cold_bps = 30;
    c.fee_hi_bps = 20;
    bad.push(("fee_lo > fee_hi", set_params_from(&kind2_core(), true, c)));
    let mut c = valid_k2_cfg();
    c.thin_rebate_mult_bps = 101;
    bad.push(("thin_rebate > skew mult", set_params_from(&kind2_core(), true, c)));
    let mut c = valid_k2_cfg();
    c.rebate_cap_bps = 301;
    bad.push(("rebate_cap > skew_cap", set_params_from(&kind2_core(), true, c)));
    let mut c = valid_k2_cfg();
    c.vol_alpha_bps = 0;
    bad.push(("alpha 0", set_params_from(&kind2_core(), true, c)));
    let mut c = valid_k2_cfg();
    c.flags = 0x80;
    bad.push(("unknown v2 flag", set_params_from(&kind2_core(), true, c)));
    bad.push((
        "kind 2 without v2 block",
        set_params_from(&kind2_core(), false, V2Config::default()),
    ));
    bad.push((
        "kind 0 with nonzero pricing fields",
        set_params_from(&init_params(0), true, valid_k2_cfg()),
    ));
    let mut p = set_params_from(&kind2_core(), true, valid_k2_cfg());
    p.kind = 3;
    bad.push(("kind 3", p));
    let mut p = set_params_from(&kind2_core(), true, valid_k2_cfg());
    p.impact_k_bps = 100; // with liquidity 0
    bad.push(("impact without depth", p));
    let mut p = set_params_from(&kind2_core(), true, valid_k2_cfg());
    p.base_spread_bps = 490; // + fee_hi 20 > max_total 500
    bad.push(("base + fee_hi > max_total", p));

    for (what, p) in &bad {
        let r = env.set_params(&lp, &ctx, p);
        assert!(r.is_err(), "{what} must be rejected");
        assert_eq!(env.ctx_data(&ctx), before, "{what}: ctx unchanged");
    }
    // enable byte not 0/1
    let mut raw = op_set_params(&set_params_from(&kind2_core(), true, valid_k2_cfg()));
    raw[1 + 69] = 2;
    assert_eq!(
        expect_err(env.configure_lp_pda(&lp, &ctx, &raw)),
        InstructionError::InvalidInstructionData
    );

    // CONTROL: the valid config is accepted, and non-config state is preserved.
    let st0 = env.ctx_struct(&ctx);
    env.set_params(&lp, &ctx, &set_params_from(&kind2_core(), true, valid_k2_cfg()))
        .unwrap();
    let st1 = env.ctx_struct(&ctx);
    assert_eq!(st1.inventory_base, st0.inventory_base);
    assert_eq!(st1.lp_account_id, st0.lp_account_id);
    assert_eq!(st1.lp_pda, st0.lp_pda);
    assert_eq!(st1.insurance_accrued_e6, st0.insurance_accrued_e6);
    assert_eq!(st1.skew_spread_mult_bps, 100);
    let b0 = st0.v2_block().unwrap();
    let b1 = st1.v2_block().unwrap();
    assert_eq!(b1.st.bound_asset_plus1, b0.st.bound_asset_plus1);
    assert_eq!(b1.cfg.thin_rebate_mult_bps, 50);
}

// -----------------------------------------------------------------------------
// owner-proof mode (auth_mode 1)
// -----------------------------------------------------------------------------

struct OwnerSetup {
    env: Env,
    owner: Keypair,
    ctx: Pubkey,
    proof: OwnerProof,
}

fn owner_setup() -> OwnerSetup {
    let mut env = Env::v2();
    let owner = seeded_keypair(40);
    let wrapper = Pubkey::new_from_array([0x77; 32]);
    let market = [0x11u8; 32];
    let portfolio = [0x22u8; 32];
    let ctx = Pubkey::new_from_array([0x99; 32]);
    let (pda, bump) = Pubkey::find_program_address(
        &[
            b"matcher",
            &market,
            &portfolio,
            owner.pubkey().as_ref(),
            PROGRAM_ID.as_ref(),
            ctx.as_ref(),
        ],
        &wrapper,
    );
    let ip = init_params(0);
    let m = MatcherCtx {
        magic: vamm::MATCHER_MAGIC,
        version: vamm::MATCHER_VERSION,
        kind: 0,
        lp_pda: pda.to_bytes(),
        trading_fee_bps: ip.trading_fee_bps,
        base_spread_bps: ip.base_spread_bps,
        max_total_bps: ip.max_total_bps,
        max_fill_abs: i128::MAX as u128,
        lp_account_id: LP_ACCOUNT_ID,
        ..MatcherCtx::default()
    };
    m.validate().expect("hand-built ctx must validate");
    let mut data = vec![0u8; MATCHER_CONTEXT_LEN];
    m.write_to(&mut data[CTX_VAMM_OFFSET..]).unwrap();
    env.svm
        .set_account(
            ctx,
            Account {
                lamports: 10_000_000,
                data,
                owner: PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    OwnerSetup {
        env,
        owner,
        ctx,
        proof: OwnerProof {
            wrapper_program_id: wrapper.to_bytes(),
            market,
            lp_portfolio: portfolio,
            bump,
        },
    }
}

#[test]
fn tag5_owner_proof_correct_seeds_succeed() {
    let mut s = owner_setup();
    let r = s
        .env
        .send(&s.owner, true, &s.ctx, owner_proof_ix(&s.proof, &op_cap(4321)));
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(cap_bytes(&s.env.ctx_data(&s.ctx)), 4321);
    // SetParams via owner proof: switch the ctx to kind 2 with a valid config
    let r = s.env.send(
        &s.owner,
        true,
        &s.ctx,
        owner_proof_ix(
            &s.proof,
            &op_set_params(&set_params_from(&kind2_core(), true, valid_k2_cfg())),
        ),
    );
    assert!(r.is_ok(), "{r:?}");
    let st = s.env.ctx_struct(&s.ctx);
    assert_eq!(st.kind, 2);
    assert_eq!(st.backing_fee_cap_bps, 4321, "SetParams preserves the cap");
    assert_eq!(cap_bytes(&s.env.ctx_data(&s.ctx)), 4321);
}

/// NEGATIVE CONTROLS: each proof ingredient changed alone -> Custom(8005); owner unsigned
/// -> MissingRequiredSignature; the owner in lp_pda mode -> InvalidAccountData. ctx
/// unchanged throughout.
#[test]
fn neg_tag5_owner_proof_wrong_ingredient_8005() {
    let mut s = owner_setup();
    let before = s.env.ctx_data(&s.ctx);
    let op = op_cap(4321);

    // wrong owner (signs, same seeds)
    let intruder = seeded_keypair(41);
    let e = expect_err(s.env.send(&intruder, true, &s.ctx, owner_proof_ix(&s.proof, &op)));
    assert_eq!(e, custom(8005), "wrong owner");

    let mut p = s.proof;
    p.market[0] ^= 1;
    let e = expect_err(s.env.send(&s.owner, true, &s.ctx, owner_proof_ix(&p, &op)));
    assert_eq!(e, custom(8005), "wrong market");

    let mut p = s.proof;
    p.lp_portfolio[31] ^= 1;
    let e = expect_err(s.env.send(&s.owner, true, &s.ctx, owner_proof_ix(&p, &op)));
    assert_eq!(e, custom(8005), "wrong portfolio");

    let mut p = s.proof;
    p.wrapper_program_id[5] ^= 1;
    let e = expect_err(s.env.send(&s.owner, true, &s.ctx, owner_proof_ix(&p, &op)));
    assert_eq!(e, custom(8005), "wrong wrapper id");

    for db in [1u8, 2, 3, 128] {
        let mut p = s.proof;
        p.bump = s.proof.bump.wrapping_sub(db);
        let e = expect_err(s.env.send(&s.owner, true, &s.ctx, owner_proof_ix(&p, &op)));
        assert_eq!(e, custom(8005), "wrong bump {}", p.bump);
    }

    let e = expect_err(s.env.send(&s.owner, false, &s.ctx, owner_proof_ix(&s.proof, &op)));
    assert_eq!(e, InstructionError::MissingRequiredSignature, "owner unsigned");

    let e = expect_err(s.env.configure_lp_pda(&s.owner, &s.ctx, &op));
    assert_eq!(e, InstructionError::InvalidAccountData, "owner is not the lp_pda");

    // truncated owner-proof header
    let mut raw = owner_proof_ix(&s.proof, &op);
    raw.truncate(99);
    let e = expect_err(s.env.send(&s.owner, true, &s.ctx, raw));
    assert_eq!(e, InstructionError::InvalidInstructionData);

    // cap > max through the owner path
    let e = expect_err(s.env.send(&s.owner, true, &s.ctx, owner_proof_ix(&s.proof, &op_cap(10_001))));
    assert_eq!(e, InstructionError::InvalidInstructionData);

    assert_eq!(s.env.ctx_data(&s.ctx), before, "every refusal left the ctx untouched");

    // CONTROL: the unmodified proof works on the same ctx afterwards
    s.env
        .send(&s.owner, true, &s.ctx, owner_proof_ix(&s.proof, &op))
        .unwrap();
    assert_eq!(cap_bytes(&s.env.ctx_data(&s.ctx)), 4321);
}

/// Owner-proof against an ordinary (keypair lp_pda) context never matches.
#[test]
fn neg_tag5_owner_proof_cannot_reach_keypair_ctx() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    let (_, bump) = Pubkey::find_program_address(
        &[b"matcher", &[1; 32], &[2; 32], lp.pubkey().as_ref(), PROGRAM_ID.as_ref(), ctx.as_ref()],
        &Pubkey::new_from_array([3; 32]),
    );
    let proof = OwnerProof {
        wrapper_program_id: [3; 32],
        market: [1; 32],
        lp_portfolio: [2; 32],
        bump,
    };
    let e = expect_err(env.send(&lp, true, &ctx, owner_proof_ix(&proof, &op_cap(5))));
    assert_eq!(e, custom(8005));
}
