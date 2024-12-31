#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::get_invoke_context;

use std::mem::transmute;
use std::sync::Arc;

use solana_sdk::account_info::AccountInfo;
use solana_sdk::entrypoint::SUCCESS;
use solana_sdk::instruction::Instruction;
use solana_sdk::instruction::InstructionError;
use solana_sdk::program_error::ProgramError;
use solana_sdk::program_error::UNSUPPORTED_SYSVAR;
use solana_sdk::program_stubs;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::stable_layout::stable_instruction::StableInstruction;
use solana_sdk::sysvar::Sysvar;

use solana_program_runtime::stable_log;
use solana_program_runtime::timings::ExecuteTimings;

pub struct TridentSyscallStubs;

impl program_stubs::SyscallStubs for TridentSyscallStubs {
    fn sol_log(&self, message: &str) {
        let invoke_context = get_invoke_context();
        let log_collector = invoke_context.get_log_collector();

        stable_log::program_log(&log_collector, message);
    }

    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        get_sysvar(get_invoke_context().get_sysvar_cache().get_rent(), var_addr)
    }
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        get_sysvar(
            get_invoke_context().get_sysvar_cache().get_clock(),
            var_addr,
        )
    }

    fn sol_get_epoch_schedule_sysvar(&self, var_addr: *mut u8) -> u64 {
        get_sysvar(
            get_invoke_context().get_sysvar_cache().get_epoch_schedule(),
            var_addr,
        )
    }

    fn sol_get_epoch_rewards_sysvar(&self, var_addr: *mut u8) -> u64 {
        get_sysvar(
            get_invoke_context().get_sysvar_cache().get_epoch_rewards(),
            var_addr,
        )
    }
    #[allow(deprecated)]
    fn sol_get_fees_sysvar(&self, var_addr: *mut u8) -> u64 {
        get_sysvar(get_invoke_context().get_sysvar_cache().get_fees(), var_addr)
    }

    fn sol_get_last_restart_slot(&self, var_addr: *mut u8) -> u64 {
        get_sysvar(
            get_invoke_context()
                .get_sysvar_cache()
                .get_last_restart_slot(),
            var_addr,
        )
    }
    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        account_infos: &[AccountInfo<'_>],
        signers_seeds: &[&[&[u8]]],
    ) -> std::result::Result<(), ProgramError> {
        let instruction = unsafe { transmute::<&Instruction, &Instruction>(instruction) };

        let account_infos =
            unsafe { transmute::<&[AccountInfo<'_>], &[AccountInfo<'_>]>(account_infos) };

        let instruction = StableInstruction::from(instruction.clone());
        let invoke_context = get_invoke_context();
        let log_collector = invoke_context.get_log_collector();
        let transaction_context = &invoke_context.transaction_context;
        let instruction_context = transaction_context
            .get_current_instruction_context()
            .unwrap();
        let caller = instruction_context
            .get_last_program_key(transaction_context)
            .unwrap();

        stable_log::program_invoke(
            &log_collector,
            &instruction.program_id,
            invoke_context.get_stack_height(),
        );

        let signers = signers_seeds
            .iter()
            .map(|seeds| Pubkey::create_program_address(seeds, caller).unwrap())
            .collect::<Vec<_>>();

        let (instruction_accounts, program_indices) = invoke_context
            .prepare_instruction(&instruction, &signers)
            .unwrap();

        // Copy caller's account_info modifications into invoke_context accounts
        let transaction_context = &invoke_context.transaction_context;
        let instruction_context = transaction_context
            .get_current_instruction_context()
            .unwrap();

        let mut account_indices = Vec::with_capacity(instruction_accounts.len());
        for instruction_account in instruction_accounts.iter() {
            let account_key = transaction_context
                .get_key_of_account_at_index(instruction_account.index_in_transaction)
                .unwrap();
            let account_info_index = account_infos
                .iter()
                .position(|account_info| account_info.unsigned_key() == account_key)
                .ok_or(InstructionError::MissingAccount)
                .unwrap();
            let account_info = &account_infos[account_info_index];
            let mut borrowed_account = instruction_context
                .try_borrow_instruction_account(
                    transaction_context,
                    instruction_account.index_in_caller,
                )
                .unwrap();
            if borrowed_account.get_lamports() != account_info.lamports() {
                borrowed_account
                    .set_lamports(account_info.lamports())
                    .unwrap();
            }
            let account_info_data = account_info.try_borrow_data().unwrap();
            // The redundant check helps to avoid the expensive data comparison if we can
            match borrowed_account
                .can_data_be_resized(account_info_data.len())
                .and_then(|_| borrowed_account.can_data_be_changed())
            {
                Ok(()) => borrowed_account
                    .set_data_from_slice(&account_info_data)
                    .unwrap(),
                Err(err) if borrowed_account.get_data() != *account_info_data => {
                    panic!("{err:?}");
                }
                _ => {}
            }
            // Change the owner at the end so that we are allowed to change the lamports and data before
            if borrowed_account.get_owner() != account_info.owner {
                borrowed_account
                    .set_owner(account_info.owner.as_ref())
                    .unwrap();
            }
            if instruction_account.is_writable {
                account_indices.push((instruction_account.index_in_caller, account_info_index));
            }
        }

        let mut compute_units_consumed = 0;

        invoke_context
            .process_instruction(
                &instruction.data,
                &instruction_accounts,
                &program_indices,
                &mut compute_units_consumed,
                &mut ExecuteTimings::default(),
            )
            .map_err(|e| convert_error(e).unwrap_or_else(|err| panic!("{}", err)))?;

        // Copy invoke_context accounts modifications into caller's account_info
        let transaction_context = &invoke_context.transaction_context;
        let instruction_context = transaction_context
            .get_current_instruction_context()
            .unwrap();
        for (index_in_caller, account_info_index) in account_indices.into_iter() {
            let borrowed_account = instruction_context
                .try_borrow_instruction_account(transaction_context, index_in_caller)
                .unwrap();
            let account_info = &account_infos[account_info_index];
            **account_info.try_borrow_mut_lamports().unwrap() = borrowed_account.get_lamports();
            if account_info.owner != borrowed_account.get_owner() {
                // TODO Figure out a better way to allow the System Program to set the account owner
                #[allow(clippy::transmute_ptr_to_ptr)]
                #[allow(mutable_transmutes)]
                let account_info_mut =
                    unsafe { transmute::<&Pubkey, &mut Pubkey>(account_info.owner) };
                *account_info_mut = *borrowed_account.get_owner();
            }

            let new_data = borrowed_account.get_data();
            let new_len = new_data.len();

            // Resize account_info data
            if account_info.data_len() != new_len {
                account_info.realloc(new_len, false).unwrap();
            }

            // Clone the data
            let mut data = account_info.try_borrow_mut_data().unwrap();

            data.clone_from_slice(new_data);
        }

        stable_log::program_success(&log_collector, &instruction.program_id);

        Ok(())
    }
    fn sol_get_return_data(&self) -> std::option::Option<(Pubkey, std::vec::Vec<u8>)> {
        let (program_id, data) = get_invoke_context().transaction_context.get_return_data();

        let program_id = unsafe { transmute::<&Pubkey, &Pubkey>(program_id) };
        Some((*program_id, data.to_vec()))
    }
    fn sol_set_return_data(&self, data: &[u8]) {
        let invoke_context = get_invoke_context();
        let transaction_context = &mut invoke_context.transaction_context;
        let instruction_context = transaction_context
            .get_current_instruction_context()
            .unwrap();
        let caller = *instruction_context
            .get_last_program_key(transaction_context)
            .unwrap();
        transaction_context
            .set_return_data(caller, data.to_vec())
            .unwrap();
    }

    fn sol_get_stack_height(&self) -> u64 {
        let invoke_context = get_invoke_context();
        invoke_context.get_stack_height().try_into().unwrap()
    }
}

fn get_sysvar<T: Default + Sysvar + Sized + serde::de::DeserializeOwned + Clone>(
    sysvar: Result<Arc<T>, InstructionError>,
    var_addr: *mut u8,
) -> u64 {
    match sysvar {
        Ok(sysvar_data) => unsafe {
            *(var_addr as *mut _ as *mut T) = T::clone(&sysvar_data);
            SUCCESS
        },
        Err(_) => UNSUPPORTED_SYSVAR,
    }
}

fn convert_error(
    error: InstructionError,
) -> Result<ProgramError, solana_sdk::instruction::InstructionError> {
    match error {
        InstructionError::GenericError => {
            Err(solana_sdk::instruction::InstructionError::GenericError)
        }
        InstructionError::InvalidArgument => Ok(ProgramError::InvalidArgument),
        InstructionError::InvalidInstructionData => Ok(ProgramError::InvalidInstructionData),
        InstructionError::InvalidAccountData => Ok(ProgramError::InvalidAccountData),
        InstructionError::AccountDataTooSmall => Ok(ProgramError::AccountDataTooSmall),
        InstructionError::InsufficientFunds => Ok(ProgramError::InsufficientFunds),
        InstructionError::IncorrectProgramId => Ok(ProgramError::IncorrectProgramId),
        InstructionError::MissingRequiredSignature => Ok(ProgramError::MissingRequiredSignature),
        InstructionError::AccountAlreadyInitialized => Ok(ProgramError::AccountAlreadyInitialized),
        InstructionError::UninitializedAccount => Ok(ProgramError::UninitializedAccount),
        InstructionError::UnbalancedInstruction => {
            Err(solana_sdk::instruction::InstructionError::UnbalancedInstruction)
        }
        InstructionError::ModifiedProgramId => {
            Err(solana_sdk::instruction::InstructionError::ModifiedProgramId)
        }
        InstructionError::ExternalAccountLamportSpend => {
            Err(solana_sdk::instruction::InstructionError::ExecutableLamportChange)
        }
        InstructionError::ExternalAccountDataModified => {
            Err(solana_sdk::instruction::InstructionError::ExternalAccountDataModified)
        }
        InstructionError::ReadonlyLamportChange => {
            Err(solana_sdk::instruction::InstructionError::ReadonlyLamportChange)
        }
        InstructionError::ReadonlyDataModified => {
            Err(solana_sdk::instruction::InstructionError::ReadonlyDataModified)
        }
        InstructionError::DuplicateAccountIndex => {
            Err(solana_sdk::instruction::InstructionError::DuplicateAccountIndex)
        }
        InstructionError::ExecutableModified => {
            Err(solana_sdk::instruction::InstructionError::ExecutableModified)
        }
        InstructionError::RentEpochModified => {
            Err(solana_sdk::instruction::InstructionError::RentEpochModified)
        }
        InstructionError::NotEnoughAccountKeys => Ok(ProgramError::NotEnoughAccountKeys),
        InstructionError::AccountDataSizeChanged => {
            Err(solana_sdk::instruction::InstructionError::AccountDataSizeChanged)
        }
        InstructionError::AccountNotExecutable => {
            Err(solana_sdk::instruction::InstructionError::AccountNotExecutable)
        }
        InstructionError::AccountBorrowFailed => Ok(ProgramError::AccountBorrowFailed),
        InstructionError::AccountBorrowOutstanding => {
            Err(solana_sdk::instruction::InstructionError::AccountBorrowOutstanding)
        }
        InstructionError::DuplicateAccountOutOfSync => {
            Err(solana_sdk::instruction::InstructionError::DuplicateAccountOutOfSync)
        }
        InstructionError::Custom(num) => Ok(ProgramError::Custom(num)),
        InstructionError::InvalidError => {
            Err(solana_sdk::instruction::InstructionError::InvalidError)
        }
        InstructionError::ExecutableDataModified => {
            Err(solana_sdk::instruction::InstructionError::ExecutableDataModified)
        }
        InstructionError::ExecutableLamportChange => {
            Err(solana_sdk::instruction::InstructionError::ExecutableLamportChange)
        }
        InstructionError::ExecutableAccountNotRentExempt => {
            Err(solana_sdk::instruction::InstructionError::ExecutableAccountNotRentExempt)
        }
        InstructionError::UnsupportedProgramId => {
            Err(solana_sdk::instruction::InstructionError::UnsupportedProgramId)
        }
        InstructionError::CallDepth => Err(solana_sdk::instruction::InstructionError::CallDepth),
        InstructionError::MissingAccount => {
            Err(solana_sdk::instruction::InstructionError::MissingAccount)
        }
        InstructionError::ReentrancyNotAllowed => {
            Err(solana_sdk::instruction::InstructionError::ReentrancyNotAllowed)
        }
        InstructionError::MaxSeedLengthExceeded => Ok(ProgramError::MaxSeedLengthExceeded),
        InstructionError::InvalidSeeds => Ok(ProgramError::InvalidSeeds),
        InstructionError::InvalidRealloc => Ok(ProgramError::InvalidRealloc),
        InstructionError::ComputationalBudgetExceeded => {
            Err(solana_sdk::instruction::InstructionError::ComputationalBudgetExceeded)
        }
        InstructionError::PrivilegeEscalation => {
            Err(solana_sdk::instruction::InstructionError::PrivilegeEscalation)
        }
        InstructionError::ProgramEnvironmentSetupFailure => {
            Err(solana_sdk::instruction::InstructionError::ProgramEnvironmentSetupFailure)
        }
        InstructionError::ProgramFailedToComplete => {
            Err(solana_sdk::instruction::InstructionError::ProgramFailedToComplete)
        }
        InstructionError::ProgramFailedToCompile => {
            Err(solana_sdk::instruction::InstructionError::ProgramFailedToCompile)
        }
        InstructionError::Immutable => Err(solana_sdk::instruction::InstructionError::Immutable),
        InstructionError::IncorrectAuthority => {
            Err(solana_sdk::instruction::InstructionError::IncorrectAuthority)
        }
        InstructionError::BorshIoError(x) => Ok(ProgramError::BorshIoError(x)),
        InstructionError::AccountNotRentExempt => Ok(ProgramError::AccountNotRentExempt),
        InstructionError::InvalidAccountOwner => Ok(ProgramError::InvalidAccountOwner),
        InstructionError::ArithmeticOverflow => Ok(ProgramError::ArithmeticOverflow),
        InstructionError::UnsupportedSysvar => Ok(ProgramError::UnsupportedSysvar),
        InstructionError::IllegalOwner => Ok(ProgramError::IllegalOwner),
        InstructionError::MaxAccountsDataAllocationsExceeded => {
            Ok(ProgramError::MaxAccountsDataAllocationsExceeded)
        }
        InstructionError::MaxAccountsExceeded => {
            Err(solana_sdk::instruction::InstructionError::MaxAccountsExceeded)
        }
        InstructionError::MaxInstructionTraceLengthExceeded => {
            Ok(ProgramError::MaxInstructionTraceLengthExceeded)
        }
        InstructionError::BuiltinProgramsMustConsumeComputeUnits => {
            Ok(ProgramError::BuiltinProgramsMustConsumeComputeUnits)
        }
    }
}
