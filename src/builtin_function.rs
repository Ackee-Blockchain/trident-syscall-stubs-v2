#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::invoke_context::set_invoke_context;
use crate::TridentSyscallStubs;

use std::collections::HashMap;
use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::sync::Once;

use solana_sdk::account_info::AccountInfo;
use solana_sdk::entrypoint::{deserialize, ProgramResult};
use solana_sdk::instruction::InstructionError;
use solana_sdk::program_stubs::set_syscall_stubs;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction_context::IndexOfAccount;

use solana_bpf_loader_program::serialization::serialize_parameters;

use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::stable_log;

pub use solana_rbpf;
pub use solana_rbpf::vm::get_runtime_environment_key;
pub use solana_rbpf::vm::EbpfVm;

static ONCE: Once = Once::new();

/// Converts a `solana-program`-style entrypoint into the runtime's entrypoint style, for
/// use with `ProgramTest::add_program`
#[macro_export]
macro_rules! processor {
    ($builtin_function:expr) => {
        Some(|vm, _arg0, _arg1, _arg2, _arg3, _arg4| {
            let vm = unsafe {
                &mut *((vm as *mut u64).offset(-($crate::get_runtime_environment_key() as isize))
                    as *mut $crate::EbpfVm<$crate::InvokeContext>)
            };
            vm.program_result =
                $crate::invoke_builtin_function($builtin_function, vm.context_object_pointer)
                    .map_err(|err| $crate::solana_rbpf::error::EbpfError::SyscallError(err))
                    .into();
        })
    };
}

pub type ProgramEntry = for<'info> fn(
    program_id: &Pubkey,
    accounts: &'info [AccountInfo<'info>],
    instruction_data: &[u8],
) -> ProgramResult;

pub fn invoke_builtin_function(
    builtin_function: ProgramEntry,
    invoke_context: &mut InvokeContext,
) -> Result<u64, Box<dyn std::error::Error>> {
    ONCE.call_once(|| {
        if std::env::var("TRIDENT_LOG").is_ok() {
            solana_logger::setup_with_default(
                "solana_rbpf::vm=debug,\
            solana_runtime::message_processor=debug,\
            solana_runtime::system_instruction_processor=trace",
            );
        } else {
            solana_logger::setup_with_default("off");
        }

        set_syscall_stubs(Box::new(TridentSyscallStubs));
    });
    set_invoke_context(invoke_context);

    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let instruction_account_indices = 0..instruction_context.get_number_of_instruction_accounts();

    // mock builtin program must consume units
    invoke_context.consume_checked(1)?;

    let log_collector = invoke_context.get_log_collector();
    let program_id = instruction_context.get_last_program_key(transaction_context)?;
    stable_log::program_invoke(
        &log_collector,
        program_id,
        invoke_context.get_stack_height(),
    );

    // Copy indices_in_instruction into a HashSet to ensure there are no duplicates
    let deduplicated_indices: HashSet<IndexOfAccount> = instruction_account_indices.collect();

    let (mut parameter_bytes, _regions, _account_lengths) = serialize_parameters(
        transaction_context,
        instruction_context,
        true, // copy_account_data // There is no VM so direct mapping can not be implemented here
    )?;

    let (program, account_infos, data) =
        unsafe { deserialize(&mut parameter_bytes.as_slice_mut()[0] as *mut u8) };

    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        builtin_function(program, &account_infos, data)
    })) {
        Ok(program_result) => {
            program_result.map_err(|program_error| {
                let err = InstructionError::from(u64::from(program_error));
                stable_log::program_failure(&log_collector, program_id, &err);
                let err: Box<dyn std::error::Error> = Box::new(err);
                err
            })?;
        }
        Err(_panic_error) => {
            let err = InstructionError::ProgramFailedToComplete;
            stable_log::program_failure(&log_collector, program_id, &err);
            let err: Box<dyn std::error::Error> = Box::new(err);
            Err(err)?;
        }
    };

    stable_log::program_success(&log_collector, program_id);

    // // Lookup table for AccountInfo
    let account_info_map: HashMap<_, _> = account_infos.iter().map(|a| (a.key, a)).collect();

    // Re-fetch the instruction context. The previous reference may have been
    // invalidated due to the `set_invoke_context` in a CPI.
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    // Commit AccountInfo changes back into KeyedAccounts
    for i in deduplicated_indices.into_iter() {
        let mut borrowed_account =
            instruction_context.try_borrow_instruction_account(transaction_context, i)?;
        if borrowed_account.is_writable() {
            if let Some(account_info) = account_info_map.get(borrowed_account.get_key()) {
                if borrowed_account.get_lamports() != account_info.lamports() {
                    borrowed_account.set_lamports(account_info.lamports())?;
                }

                if borrowed_account
                    .can_data_be_resized(account_info.data_len())
                    .is_ok()
                    && borrowed_account.can_data_be_changed().is_ok()
                {
                    borrowed_account.set_data_from_slice(&account_info.data.borrow())?;
                }
                if borrowed_account.get_owner() != account_info.owner {
                    borrowed_account.set_owner(account_info.owner.as_ref())?;
                }
            }
        }
    }

    Ok(0)
}
