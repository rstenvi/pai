use crate::{
	api::{
		messages::{Event, EventInner, RegEvent},
		ArgsBuilder, Client, Command, Response,
	},
	ctx,
	plugin::Plugin,
	utils, Result, TargetPtr,
};

#[derive(Default)]
pub struct Reads;

impl Reads {
	fn new() -> Self {
		Self
	}
	pub fn dependecies() -> Vec<Plugin> {
		vec![Plugin::Files]
	}
	pub fn init(client: crate::Client) -> Result<ctx::Secondary<Self, crate::Error>> {
		log::error!("read plugin is not finished and will not give expected results");
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;
		let client = ctx.client_mut();

		let read = client.resolve_syscall("read")?;
		let pread = client.resolve_syscall("pread");
		let pread64 = client.resolve_syscall("pread64");
		let readv = client.resolve_syscall("readv");
		let preadv = client.resolve_syscall("preadv");
		let preadv2 = client.resolve_syscall("preadv2");

		Ok(ctx)
	}
}
