

use std::borrow::Borrow;

use bitcoin::FeeRate;

pub trait FeeRateExt: Borrow<FeeRate> + Copy {
	fn to_bdk(self) -> bdk::FeeRate {
		bdk::FeeRate::from_sat_per_kwu(self.borrow().to_sat_per_kwu() as f32)
	}
}

impl FeeRateExt for FeeRate {}
