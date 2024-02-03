use crate::TargetPtr;

pub mod ptrace;

pub struct SwBp {
	addr: TargetPtr,
	oldcode: Vec<u8>,
	numhits: Option<usize>,
	clients: Vec<usize>,
}
impl std::fmt::Debug for SwBp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SwBp")
			.field("addr", &format_args!("{:x}", self.addr))
			.field("oldcode", &self.oldcode)
			.finish()
	}
}
impl SwBp {
	#[cfg(any())]
	pub fn new_recurr(addr: TargetPtr, oldcode: Vec<u8>) -> Self {
		Self {
			addr,
			oldcode,
			numhits: None,
			clients: Vec::new(),
		}
	}
	pub fn new_limit(addr: TargetPtr, oldcode: Vec<u8>, numhits: usize) -> Self {
		Self {
			addr,
			oldcode,
			numhits: Some(numhits),
			clients: Vec::new(),
		}
	}
	pub fn add_client(&mut self, cid: usize) {
		self.clients.push(cid);
	}
	pub fn hit(&mut self) {
		if let Some(n) = &mut self.numhits {
			if *n == 0 {
				log::trace!("hit BP after set to 0");
			} else {
				*n -= 1;
			}
		}
	}
	pub fn should_remove(&self) -> bool {
		self.numhits == Some(0)
	}
}
