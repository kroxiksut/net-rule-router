//! The order the Windows installers see between builds. An older pre-release
//! that ranks equal or higher installs over a newer one, whose database it
//! then cannot open.

#[allow(dead_code)]
mod rank {
    include!("../../../packaging/windows/version_rank.rs");
}

use rank::prerelease_rank;

#[test]
fn every_later_build_ranks_higher() {
    let order = [
        "dev", "alpha", "alpha.1", "alpha.2", "alpha.28", "beta", "beta.1", "beta.29", "rc",
        "rc.1", "rc.29", "",
    ];
    let ranks: Vec<u16> = order
        .iter()
        .map(|pre| prerelease_rank(pre).unwrap_or_else(|e| panic!("{pre}: {e}")))
        .collect();
    for (pair, names) in ranks.windows(2).zip(order.windows(2)) {
        assert!(pair[0] < pair[1], "{names:?} ranked {pair:?}");
    }
    assert!(
        ranks.iter().all(|r| *r <= 99),
        "the MSI third field holds c*100 + rank"
    );
}

#[test]
fn a_pre_release_the_installers_cannot_order_stops_the_build() {
    for pre in [
        "preview",
        "alpha.x",
        "alpha.29",
        "rc.30",
        "dev.1",
        "alpha.1.2",
    ] {
        assert!(prerelease_rank(pre).is_err(), "{pre}");
    }
}
