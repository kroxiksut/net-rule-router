//! Byte counts as people read them (`formatStorageBytes` in `pure.js`).

const KIB: u128 = 1024;
const MIB: u128 = KIB * 1024;
const GIB: u128 = MIB * 1024;

/// `value / unit` to `places` decimals, rounding a tie up as JS `toFixed`
/// does for a positive number. Integer arithmetic, so no binary rounding.
fn fixed(value: u128, unit: u128, places: u32) -> String {
    let scale = 10u128.pow(places);
    let scaled = (value * scale * 2 + unit) / (unit * 2);
    let width = places as usize;
    format!("{}.{:0width$}", scaled / scale, scaled % scale)
}

/// `512 B`, `1.5 KiB`, `12.3 MiB`, `2.05 GiB`.
pub fn format_storage_bytes(bytes: u64) -> String {
    let n = u128::from(bytes);
    if n < KIB {
        format!("{n} B")
    } else if n < MIB {
        format!("{} KiB", fixed(n, KIB, 1))
    } else if n < GIB {
        format!("{} MiB", fixed(n, MIB, 1))
    } else {
        format!("{} GiB", fixed(n, GIB, 2))
    }
}

#[cfg(test)]
mod tests {
    use super::format_storage_bytes;

    #[test]
    fn a_tie_rounds_up_like_to_fixed() {
        // 1280 / 1024 = 1.25 exactly; JS prints 1.3.
        assert_eq!(format_storage_bytes(1280), "1.3 KiB");
        assert_eq!(format_storage_bytes(1023), "1023 B");
        assert_eq!(format_storage_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }
}
