use anyhow::Context;
use tss_esapi::{
    abstraction::nv,
    handles::{NvIndexHandle, NvIndexTpmHandle, ObjectHandle},
    interface_types::{
        resource_handles::{NvAuth, Provision},
        session_handles::AuthSession,
    },
    structures::MaxNvBuffer,
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

pub fn get_session_context() -> anyhow::Result<tss_esapi::Context> {
    let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    Ok(ctx)
}

pub fn tpm2_read(
    value: u32,
    ctx: std::option::Option<&mut tss_esapi::Context>,
) -> anyhow::Result<Vec<u8>> {
    let index_handle = NvIndexTpmHandle::new(value).context("unable to initialize TPM handle")?;

    let mut ctx: &mut tss_esapi::Context = match ctx {
        Some(c) => c,
        None => &mut get_session_context()?,
    };

    nv::read_full(&mut ctx, NvAuth::Owner, index_handle)
        .context("unable to read non-volatile vTPM data")
}

use thiserror::Error;
#[derive(Error, Debug)]
pub enum IndexError {
    #[error("NV index, not found")]
    NotFound,

    #[error("NV index, memory area size mismatch")]
    SizeMismatch,
}

/**
 * checks if an NV index exists in TPM memory and optionally if its size matches
 */
fn find_index(
    index: NvIndexTpmHandle,
    size_opt: std::option::Option<usize>,
    ctx: &mut tss_esapi::Context,
) -> anyhow::Result<(), anyhow::Error> {
    let list = nv::list(ctx)?;
    let result = list
        .iter()
        .find(|(nv_public, _)| nv_public.nv_index() == index);

    let Some((nv_public, _)) = result else {
        return Err(IndexError::NotFound.into());
    };

    if let Some(size) = size_opt
        && nv_public.data_size() != size
    {
        return Err(IndexError::SizeMismatch.into());
    }

    Ok(())
}

/**
 * resolves a TPM NV index to an ESYS (API) TPM Resource handle in order to interact with it
 */
pub fn resolve_handle(
    value: u32,
    ctx: std::option::Option<&mut tss_esapi::Context>,
) -> anyhow::Result<ObjectHandle> {
    let ctx: &mut tss_esapi::Context = match ctx {
        Some(c) => c,
        None => &mut get_session_context()?,
    };
    let index_handle = NvIndexTpmHandle::new(value)?;

    Ok(ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(index_handle.into()))?)
}

/**
 * creates a location in nv memory ("area") and links it to the provided index with an "handle"
 * if already exists with different size, delete and recreate
*/
pub fn create_index(
    index_handle: NvIndexTpmHandle,
    size: usize,
    ctx: std::option::Option<&mut tss_esapi::Context>,
) -> anyhow::Result<NvIndexHandle> {
    let ctx: &mut tss_esapi::Context = match ctx {
        Some(c) => c,
        None => &mut get_session_context()?,
    };

    let attr = tss_esapi::attributes::NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .build()?;

    let owner = tss_esapi::structures::NvPublicBuilder::new()
        .with_nv_index(index_handle)
        .with_index_name_algorithm(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
        .with_index_attributes(attr)
        .with_data_area_size(size)
        .build()?;

    Ok(ctx.nv_define_space(Provision::Owner, None, owner)?)
}

pub fn delete_index(
    value: u32,
    ctx: std::option::Option<&mut tss_esapi::Context>,
) -> anyhow::Result<()> {
    let mut ctx: &mut tss_esapi::Context = match ctx {
        Some(c) => c,
        None => &mut get_session_context()?,
    };

    let esys_nv_tr_handle = resolve_handle(value, Some(&mut ctx))?;
    ctx.nv_undefine_space(Provision::Owner, esys_nv_tr_handle.into())?;

    Ok(())
}

pub fn tpm2_write(value: u32, bytes: &[u8]) -> anyhow::Result<()> {
    let mut ctx = get_session_context()?;
    let buffer = MaxNvBuffer::try_from(bytes)?;
    let auth = NvAuth::Owner;

    let nvindex_handle = NvIndexTpmHandle::new(value)?;
    let esys_nv_tr_handle: NvIndexHandle;

    let index = find_index(nvindex_handle, Some(bytes.len()), &mut ctx);
    if let Err(ref e) = index {
        esys_nv_tr_handle = match e.downcast_ref::<IndexError>() {
            Some(IndexError::NotFound) => {
                create_index(nvindex_handle, buffer.len(), Some(&mut ctx))?
            }
            Some(IndexError::SizeMismatch) => {
                delete_index(value, Some(&mut ctx))?;
                create_index(nvindex_handle, buffer.len(), Some(&mut ctx))?
            }
            _ => return Err(index.unwrap_err()),
        };
    } else {
        esys_nv_tr_handle = resolve_handle(value, Some(&mut ctx))?.into();
    }

    ctx.nv_write(auth, esys_nv_tr_handle.into(), buffer, 0)?;
    Ok(())
}

pub fn tpm2_get_pcrs(
    pcr_selection_list: tss_esapi::structures::PcrSelectionList,
    ctx: std::option::Option<&mut tss_esapi::Context>,
) -> anyhow::Result<tss_esapi::abstraction::pcr::PcrData> {
    let ctx: &mut tss_esapi::Context = match ctx {
        Some(c) => c,
        None => &mut get_session_context()?,
    };

    Ok(ctx.execute_without_session(|ctx| {
        tss_esapi::abstraction::pcr::read_all(ctx, pcr_selection_list)
    })?)
}
