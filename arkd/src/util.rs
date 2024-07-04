

use std::borrow::Borrow;

use bitcoin::FeeRate;

pub trait FeeRateExt: Borrow<FeeRate> + Copy {
	fn to_bdk(self) -> bitcoin::FeeRate {
		bitcoin::FeeRate::from_sat_per_kwu(self.borrow().to_sat_per_kwu())
	}
}

impl FeeRateExt for FeeRate {}
