//! EIP-712 typed data formatting — parses structured typed data and produces
//! a [`DisplayModel`](crate::engine::DisplayModel) using the same descriptor format as calldata.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::encryption::{
    fallback_text, validate_annotation, Decryption, DecryptionCache, PlainKind,
};
use crate::engine::{
    ensure_single_nested_param_source, normalized_nested_calldata, parse_nested_address_param,
    parse_nested_amount_literal, parse_nested_selector_param, uint_bytes_from_biguint,
    with_field_encryption, DisplayEntry, DisplayItem, DisplayModel, GroupIteration,
};
use crate::error::Error;
use crate::outcome::{render_warning, FormatDiagnostic, RenderDiagnosticKind, RenderState};
use crate::path::{apply_collection_access, CollectionSelection};
use crate::provider::DataProvider;
use crate::render_shared::{
    chain_name, coerce_unsigned_biguint_from_typed_value,
    coerce_unsigned_decimal_string_from_typed_value, format_blockheight_timestamp,
    format_duration_seconds, format_timestamp, format_token_amount_output, format_unit_biguint,
    format_with_decimals, is_excluded_path, lookup_map_entry, native_token_meta,
    parse_unsigned_biguint_from_typed_value, resolve_interpolation_field_spec,
    resolve_metadata_constant_str,
};
use crate::resolver::ResolvedDescriptor;
use crate::types::descriptor::Descriptor;
use crate::types::display::{
    DisplayField, DisplayFormat, EncryptionParams, FieldFormat, FieldGroup, FormatParams,
    Iteration, VisibleLiteral, VisibleRule,
};

/// Maximum recursion depth for nested calldata in EIP-712 context.
const MAX_CALLDATA_DEPTH: u8 = 3;

type RenderDiagnostics = Vec<FormatDiagnostic>;

/// EIP-712 typed data as received for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
    pub types: HashMap<String, Vec<TypedDataField>>,

    #[serde(rename = "primaryType")]
    pub primary_type: String,

    pub domain: TypedDataDomain,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<TypedDataContainer>,

    pub message: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypedDataContainer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataField {
    pub name: String,

    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataDomain {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(rename = "chainId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, deserialize_with = "deserialize_chain_id")]
    pub chain_id: Option<u64>,

    #[serde(rename = "verifyingContract")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,

    #[serde(flatten, default)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Copy)]
struct TypedContainerContext<'a> {
    chain_id: Option<u64>,
    verifying_contract: Option<&'a str>,
    from: Option<&'a str>,
    /// Decryptions already resolved for this message — a field is read for
    /// visibility, for its entry and for `interpolatedIntent`, and the wallet
    /// must only be asked once. Rides on the container because the container is
    /// what already reaches every typed renderer.
    decryption: &'a DecryptionCache,
}

impl<'a> TypedContainerContext<'a> {
    fn from_typed_data(data: &'a TypedData, decryption: &'a DecryptionCache) -> Self {
        Self {
            chain_id: data.domain.chain_id,
            verifying_contract: data.domain.verifying_contract.as_deref(),
            from: data
                .container
                .as_ref()
                .and_then(|container| container.from.as_deref()),
            decryption,
        }
    }
}

/// Deserialize chainId that may be a number or a hex string (e.g. "0xa" for 10).
fn deserialize_chain_id<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct ChainIdVisitor;

    impl<'de> de::Visitor<'de> for ChainIdVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a number or hex string for chainId")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v as u64))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let trimmed = v.trim();
            if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)
                    .map(Some)
                    .map_err(de::Error::custom)
            } else {
                trimmed.parse::<u64>().map(Some).map_err(de::Error::custom)
            }
        }
    }

    deserializer.deserialize_any(ChainIdVisitor)
}

/// Format EIP-712 typed data into a display model.
///
/// `descriptors` provides pre-resolved inner descriptors for nested calldata support.
pub async fn format_typed_data(
    descriptor: &Descriptor,
    data: &TypedData,
    data_provider: &dyn DataProvider,
    descriptors: &[ResolvedDescriptor],
) -> Result<DisplayModel, Error> {
    let format = find_typed_format(descriptor, data)?;
    let mut state = RenderState::default();
    format_typed_data_with_format(
        descriptor,
        data,
        format,
        data_provider,
        descriptors,
        &mut state,
    )
    .await
}

pub(crate) async fn format_typed_data_with_format(
    descriptor: &Descriptor,
    data: &TypedData,
    format: &DisplayFormat,
    data_provider: &dyn DataProvider,
    descriptors: &[ResolvedDescriptor],
    state: &mut RenderState,
) -> Result<DisplayModel, Error> {
    let decryption = DecryptionCache::default();
    let container = TypedContainerContext::from_typed_data(data, &decryption);
    let mut warnings = RenderDiagnostics::new();
    let mut nested_fallback = false;
    let expanded_fields =
        crate::engine::expand_display_fields(descriptor, &format.fields, &mut warnings);
    let renderable_fields = filter_excluded_fields(&expanded_fields, &format.excluded);
    let entries = render_typed_fields(
        descriptor,
        &data.message,
        &renderable_fields,
        container,
        data_provider,
        &mut warnings,
        descriptors,
        0,
        &mut nested_fallback,
    )
    .await?;

    let model = DisplayModel {
        intent: format
            .intent
            .as_ref()
            .map(crate::types::display::intent_as_string)
            .unwrap_or_else(|| data.primary_type.clone()),
        interpolated_intent: match format.interpolated_intent.as_ref() {
            Some(template) => match interpolate_typed_intent(
                template,
                descriptor,
                &data.message,
                container,
                &expanded_fields,
                &format.excluded,
                data_provider,
            )
            .await
            {
                Ok(rendered) => Some(rendered),
                Err(err) => {
                    warnings.push(render_warning(
                        RenderDiagnosticKind::InterpolatedIntentSkipped,
                        format!("interpolated intent skipped: {err}"),
                    ));
                    None
                }
            },
            None => None,
        },
        entries,
        owner: descriptor.metadata.owner.clone(),
        contract_name: descriptor.metadata.contract_name.clone(),
    };

    crate::engine::record_diagnostics(state, &warnings);
    if nested_fallback {
        state.mark_nested_fallback();
    }

    Ok(model)
}

pub(crate) fn validate_descriptor_domain_binding(
    descriptor: &Descriptor,
    data: &TypedData,
) -> Result<(), Error> {
    crate::eip712_domain::validate_descriptor_eip712_context(descriptor, data)
}

fn filter_excluded_fields(fields: &[DisplayField], excluded: &[String]) -> Vec<DisplayField> {
    fields
        .iter()
        .filter_map(|field| match field {
            DisplayField::Simple {
                path: Some(path), ..
            } if is_excluded_path(excluded, path) => None,
            DisplayField::Group { field_group } => Some(DisplayField::Group {
                field_group: FieldGroup {
                    path: field_group.path.clone(),
                    label: field_group.label.clone(),
                    iteration: field_group.iteration.clone(),
                    fields: filter_excluded_fields(&field_group.fields, excluded),
                },
            }),
            DisplayField::Scope {
                path,
                label,
                iteration,
                fields,
            } => Some(DisplayField::Scope {
                path: path.clone(),
                label: label.clone(),
                iteration: iteration.clone(),
                fields: filter_excluded_fields(fields, excluded),
            }),
            _ => Some(field.clone()),
        })
        .collect()
}

/// Render typed data fields recursively.
///
/// Uses `Pin<Box<dyn Future>>` to support recursive calls.
#[allow(clippy::too_many_arguments)]
fn render_typed_fields<'a>(
    descriptor: &'a Descriptor,
    message: &'a serde_json::Value,
    fields: &[DisplayField],
    container: TypedContainerContext<'a>,
    data_provider: &'a dyn DataProvider,
    warnings: &'a mut RenderDiagnostics,
    descriptors: &'a [ResolvedDescriptor],
    depth: u8,
    nested_fallback: &'a mut bool,
) -> Pin<Box<dyn Future<Output = Result<Vec<DisplayEntry>, Error>> + Send + 'a>> {
    let fields = fields.to_vec();
    Box::pin(async move {
        let mut entries = Vec::new();

        for field in &fields {
            match field {
                DisplayField::Group { field_group } => {
                    entries.extend(
                        render_typed_field_group_entries(
                            descriptor,
                            message,
                            field_group,
                            container,
                            data_provider,
                            warnings,
                            descriptors,
                            depth,
                            nested_fallback,
                        )
                        .await?,
                    );
                }
                DisplayField::Simple {
                    path,
                    label,
                    value: literal_value,
                    format,
                    params,
                    encryption,
                    separator: _,
                    visible,
                } => {
                    let params = with_field_encryption(params, encryption);
                    // If literal value is provided (no path), resolve constant refs and use it
                    if let Some(lit) = literal_value {
                        if !check_typed_visibility(visible, &None, label, "")? {
                            continue;
                        }
                        let resolved = resolve_metadata_constant_str(descriptor, lit);
                        entries.push(DisplayEntry::Item(DisplayItem::new(
                            label.clone(),
                            resolved,
                        )));
                        continue;
                    }

                    let path_str = path.as_deref().unwrap_or("");

                    // Check for .[] array iteration — expand into one entry per element
                    if let Some((base, rest)) = crate::engine::split_array_iter_path(path_str) {
                        if let Some(serde_json::Value::Array(items)) =
                            resolve_typed_path_in_context(message, base, container)?
                        {
                            for (i, item) in items.iter().enumerate() {
                                let val = if rest.is_empty() {
                                    Some(item.clone())
                                } else {
                                    resolve_typed_path_in_context(item, rest, container)?
                                };
                                // Flat array path: rewrite element-relative param
                                // paths (`x.[].token`) to the concrete index and
                                // resolve against the root, matching the calldata
                                // path. A bare root path (no `.[]`) stays root-relative.
                                let item_params =
                                    crate::engine::index_array_params(params.as_ref(), i);
                                if !is_typed_field_visible(
                                    visible,
                                    &val,
                                    item_params.as_ref(),
                                    label,
                                    path_str,
                                    container,
                                    data_provider,
                                    warnings,
                                )
                                .await?
                                {
                                    continue;
                                }
                                let formatted = format_typed_value(
                                    descriptor,
                                    &val,
                                    format.as_ref(),
                                    item_params.as_ref(),
                                    container,
                                    message,
                                    None,
                                    data_provider,
                                    warnings,
                                )
                                .await?;
                                entries.push(DisplayEntry::Item(DisplayItem {
                                    label: label.clone(),
                                    value: formatted,
                                    raw_encrypted_value: typed_raw_encrypted_value(
                                        &val,
                                        item_params.as_ref(),
                                    ),
                                }));
                            }
                            continue;
                        }
                    }

                    let value = resolve_typed_path_in_context(message, path_str, container)?;

                    // Check visibility
                    if !is_typed_field_visible(
                        visible,
                        &value,
                        params.as_ref(),
                        label,
                        path_str,
                        container,
                        data_provider,
                        warnings,
                    )
                    .await?
                    {
                        continue;
                    }

                    // Intercept calldata format
                    if matches!(format.as_ref(), Some(FieldFormat::Calldata)) {
                        let entry = render_typed_calldata_field(
                            descriptor,
                            message,
                            &value,
                            params.as_ref(),
                            label,
                            container,
                            data_provider,
                            descriptors,
                            depth,
                            warnings,
                            nested_fallback,
                        )
                        .await?;
                        entries.push(entry);
                        continue;
                    }

                    let formatted = format_typed_value(
                        descriptor,
                        &value,
                        format.as_ref(),
                        params.as_ref(),
                        container,
                        message,
                        None,
                        data_provider,
                        warnings,
                    )
                    .await?;

                    entries.push(DisplayEntry::Item(DisplayItem {
                        label: label.clone(),
                        value: formatted,
                        raw_encrypted_value: typed_raw_encrypted_value(&value, params.as_ref()),
                    }));
                }
                DisplayField::Reference { .. } | DisplayField::Scope { .. } => {
                    warnings.push(render_warning(
                        RenderDiagnosticKind::GenericRenderWarning,
                        "unexpanded display field reached typed renderer; skipping",
                    ));
                }
            }
        }

        Ok(entries)
    })
}

enum TypedGroupRenderKind {
    Scalar(Vec<DisplayItem>),
    Bundles(Vec<Vec<DisplayItem>>),
}

#[allow(clippy::too_many_arguments)]
fn render_typed_group_field_kind<'a>(
    descriptor: &'a Descriptor,
    message: &'a serde_json::Value,
    field: &'a DisplayField,
    container: TypedContainerContext<'a>,
    data_provider: &'a dyn DataProvider,
    warnings: &'a mut RenderDiagnostics,
    descriptors: &'a [ResolvedDescriptor],
    depth: u8,
    nested_fallback: &'a mut bool,
) -> Pin<Box<dyn Future<Output = Result<TypedGroupRenderKind, Error>> + Send + 'a>> {
    Box::pin(async move {
        match field {
            DisplayField::Group { field_group } => {
                render_typed_group_kind(
                    descriptor,
                    message,
                    field_group,
                    container,
                    data_provider,
                    warnings,
                    descriptors,
                    depth,
                    nested_fallback,
                )
                .await
            }
            DisplayField::Simple {
                path,
                label,
                value: literal_value,
                format,
                params,
                encryption,
                separator: _,
                visible,
            } => {
                let params = with_field_encryption(params, encryption);
                if let Some(lit) = literal_value {
                    if !check_typed_visibility(visible, &None, label, "")? {
                        return Ok(TypedGroupRenderKind::Scalar(Vec::new()));
                    }
                    return Ok(TypedGroupRenderKind::Scalar(vec![DisplayItem::new(
                        label.clone(),
                        resolve_metadata_constant_str(descriptor, lit),
                    )]));
                }

                let path_str = path.as_deref().unwrap_or("");
                if let Some((base, rest)) = crate::engine::split_array_iter_path(path_str) {
                    if let Some(serde_json::Value::Array(items)) =
                        resolve_typed_path_in_context(message, base, container)?
                    {
                        let mut bundles = Vec::new();
                        for item in &items {
                            let val = if rest.is_empty() {
                                Some(item.clone())
                            } else {
                                resolve_typed_path_in_context(item, rest, container)?
                            };
                            let item_params = item_scoped_typed_params(base, params.as_ref());
                            if !is_typed_field_visible(
                                visible,
                                &val,
                                item_params.as_ref(),
                                label,
                                path_str,
                                container,
                                data_provider,
                                warnings,
                            )
                            .await?
                            {
                                // Keep the slot so bundled groups stay aligned.
                                bundles.push(Vec::new());
                                continue;
                            }
                            let rendered = if matches!(format.as_ref(), Some(FieldFormat::Calldata))
                            {
                                crate::engine::flatten_display_entry(
                                    render_typed_calldata_field(
                                        descriptor,
                                        message,
                                        &val,
                                        item_params.as_ref(),
                                        label,
                                        container,
                                        data_provider,
                                        descriptors,
                                        depth,
                                        warnings,
                                        nested_fallback,
                                    )
                                    .await?,
                                )
                            } else {
                                vec![DisplayItem {
                                    label: label.clone(),
                                    value: format_typed_value(
                                        descriptor,
                                        &val,
                                        format.as_ref(),
                                        item_params.as_ref(),
                                        container,
                                        message,
                                        Some(item),
                                        data_provider,
                                        warnings,
                                    )
                                    .await?,
                                    raw_encrypted_value: typed_raw_encrypted_value(
                                        &val,
                                        item_params.as_ref(),
                                    ),
                                }]
                            };
                            bundles.push(rendered);
                        }
                        return Ok(TypedGroupRenderKind::Bundles(bundles));
                    }
                }

                let value = resolve_typed_path_in_context(message, path_str, container)?;
                if !is_typed_field_visible(
                    visible,
                    &value,
                    params.as_ref(),
                    label,
                    path_str,
                    container,
                    data_provider,
                    warnings,
                )
                .await?
                {
                    return Ok(TypedGroupRenderKind::Scalar(Vec::new()));
                }

                if matches!(format.as_ref(), Some(FieldFormat::Calldata)) {
                    return Ok(TypedGroupRenderKind::Scalar(
                        crate::engine::flatten_display_entry(
                            render_typed_calldata_field(
                                descriptor,
                                message,
                                &value,
                                params.as_ref(),
                                label,
                                container,
                                data_provider,
                                descriptors,
                                depth,
                                warnings,
                                nested_fallback,
                            )
                            .await?,
                        ),
                    ));
                }

                Ok(TypedGroupRenderKind::Scalar(vec![DisplayItem {
                    label: label.clone(),
                    value: format_typed_value(
                        descriptor,
                        &value,
                        format.as_ref(),
                        params.as_ref(),
                        container,
                        message,
                        None,
                        data_provider,
                        warnings,
                    )
                    .await?,
                    raw_encrypted_value: typed_raw_encrypted_value(&value, params.as_ref()),
                }]))
            }
            DisplayField::Reference { .. } | DisplayField::Scope { .. } => {
                Ok(TypedGroupRenderKind::Scalar(Vec::new()))
            }
        }
    })
}

fn item_scoped_typed_params(base: &str, params: Option<&FormatParams>) -> Option<FormatParams> {
    let mut params = params.cloned()?;

    if let Some(token_path) = params.token_path.as_ref() {
        let prefix = format!("{base}.[].");
        if let Some(item_relative) = token_path.strip_prefix(&prefix) {
            params.token_path = Some(item_relative.to_string());
        }
    }

    Some(params)
}

fn resolve_typed_param_path_in_context(
    message: &serde_json::Value,
    path: &str,
    container: TypedContainerContext<'_>,
    item_scope: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, Error> {
    if path.starts_with("#.") || path.starts_with("@.") {
        return resolve_typed_path_in_context(message, path, container);
    }

    if let Some(item_scope) = item_scope {
        return Ok(resolve_typed_message_path(item_scope, path));
    }

    resolve_typed_path_in_context(message, path, container)
}

#[allow(clippy::too_many_arguments)]
fn render_typed_group_kind<'a>(
    descriptor: &'a Descriptor,
    message: &'a serde_json::Value,
    group: &'a FieldGroup,
    container: TypedContainerContext<'a>,
    data_provider: &'a dyn DataProvider,
    warnings: &'a mut RenderDiagnostics,
    descriptors: &'a [ResolvedDescriptor],
    depth: u8,
    nested_fallback: &'a mut bool,
) -> Pin<Box<dyn Future<Output = Result<TypedGroupRenderKind, Error>> + Send + 'a>> {
    Box::pin(async move {
        let mut child_kinds = Vec::new();
        for field in &group.fields {
            child_kinds.push(
                render_typed_group_field_kind(
                    descriptor,
                    message,
                    field,
                    container,
                    data_provider,
                    warnings,
                    descriptors,
                    depth,
                    nested_fallback,
                )
                .await?,
            );
        }

        match group.iteration {
            Iteration::Sequential => {
                let all_bundles = !child_kinds.is_empty()
                    && child_kinds
                        .iter()
                        .all(|k| matches!(k, TypedGroupRenderKind::Bundles(_)));
                let items = if all_bundles {
                    // Element-major: keep each array element's fields contiguous
                    // (e.g. [amount0, addr0, amount1, addr1]) rather than grouping
                    // all of one field's elements together.
                    let mut sets: Vec<_> = child_kinds
                        .into_iter()
                        .map(|k| match k {
                            TypedGroupRenderKind::Bundles(b) => b,
                            TypedGroupRenderKind::Scalar(_) => Vec::new(),
                        })
                        .collect();
                    let element_count = sets.iter().map(Vec::len).max().unwrap_or(0);
                    let mut items = Vec::new();
                    for i in 0..element_count {
                        for set in sets.iter_mut() {
                            if i < set.len() {
                                items.append(&mut set[i]);
                            }
                        }
                    }
                    items
                } else {
                    child_kinds
                        .into_iter()
                        .flat_map(|kind| match kind {
                            TypedGroupRenderKind::Scalar(items) => items,
                            TypedGroupRenderKind::Bundles(bundles) => {
                                bundles.into_iter().flatten().collect()
                            }
                        })
                        .collect()
                };
                Ok(TypedGroupRenderKind::Scalar(items))
            }
            Iteration::Bundled => {
                let mut bundle_sets = Vec::new();
                for kind in child_kinds {
                    match kind {
                        TypedGroupRenderKind::Bundles(bundles) => bundle_sets.push(bundles),
                        TypedGroupRenderKind::Scalar(_) => {
                            return Err(Error::Render(
                                "bundled groups cannot mix array-expanded and scalar fields"
                                    .to_string(),
                            ));
                        }
                    }
                }

                if bundle_sets.is_empty() {
                    return Ok(TypedGroupRenderKind::Bundles(Vec::new()));
                }

                let expected_len = bundle_sets[0].len();
                if bundle_sets
                    .iter()
                    .any(|bundles| bundles.len() != expected_len)
                {
                    return Err(Error::Render(
                        "bundled groups require all array-expanded fields to have the same length"
                            .to_string(),
                    ));
                }

                let mut bundled = vec![Vec::new(); expected_len];
                for bundles in bundle_sets {
                    for (index, items) in bundles.into_iter().enumerate() {
                        bundled[index].extend(items);
                    }
                }
                Ok(TypedGroupRenderKind::Bundles(bundled))
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn render_typed_field_group_entries<'a>(
    descriptor: &'a Descriptor,
    message: &'a serde_json::Value,
    group: &FieldGroup,
    container: TypedContainerContext<'a>,
    data_provider: &'a dyn DataProvider,
    warnings: &'a mut RenderDiagnostics,
    descriptors: &'a [ResolvedDescriptor],
    depth: u8,
    nested_fallback: &'a mut bool,
) -> Result<Vec<DisplayEntry>, Error> {
    let rendered = render_typed_group_kind(
        descriptor,
        message,
        group,
        container,
        data_provider,
        warnings,
        descriptors,
        depth,
        nested_fallback,
    )
    .await?;
    match rendered {
        TypedGroupRenderKind::Scalar(items) => {
            if items.is_empty() {
                return Ok(Vec::new());
            }
            if let Some(label) = group.label.as_ref() {
                Ok(vec![DisplayEntry::Group {
                    label: label.clone(),
                    iteration: GroupIteration::Sequential,
                    items,
                }])
            } else {
                Ok(items.into_iter().map(DisplayEntry::Item).collect())
            }
        }
        TypedGroupRenderKind::Bundles(bundles) => {
            let items: Vec<DisplayItem> = bundles.into_iter().flatten().collect();
            if items.is_empty() {
                return Ok(Vec::new());
            }
            Ok(vec![DisplayEntry::Group {
                label: group.label.clone().unwrap_or_default(),
                iteration: GroupIteration::Bundled,
                items,
            }])
        }
    }
}

/// Render a nested calldata field within EIP-712 typed data.
///
/// The `#.` path prefix resolves from message fields (EIP-712 specific).
#[allow(clippy::too_many_arguments)]
async fn render_typed_calldata_field(
    _descriptor: &Descriptor,
    message: &serde_json::Value,
    val: &Option<serde_json::Value>,
    params: Option<&FormatParams>,
    label: &str,
    container: TypedContainerContext<'_>,
    data_provider: &dyn DataProvider,
    descriptors: &[ResolvedDescriptor],
    depth: u8,
    warnings: &mut RenderDiagnostics,
    nested_fallback: &mut bool,
) -> Result<DisplayEntry, Error> {
    // Extract hex bytes from JSON value
    let inner_calldata = match val {
        Some(serde_json::Value::String(s)) => {
            let hex_str = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            match hex::decode(hex_str) {
                Ok(bytes) => bytes,
                Err(_) => {
                    warnings.push(render_warning(
                        RenderDiagnosticKind::NestedCalldataDegraded,
                        "could not decode calldata hex",
                    ));
                    *nested_fallback = true;
                    return Ok(DisplayEntry::Item(DisplayItem::new(
                        label.to_string(),
                        s.clone(),
                    )));
                }
            }
        }
        _ => {
            let raw = val
                .as_ref()
                .map(json_value_to_string)
                .unwrap_or_else(|| "<unresolved>".to_string());
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedCalldataInvalidType,
                "calldata field is not a hex string",
            ));
            *nested_fallback = true;
            return Ok(DisplayEntry::Item(DisplayItem::new(label.to_string(), raw)));
        }
    };

    // Check depth limit
    if depth >= MAX_CALLDATA_DEPTH {
        warnings.push(render_warning(
            RenderDiagnosticKind::NestedCalldataDegraded,
            format!(
                "nested calldata depth limit ({}) reached",
                MAX_CALLDATA_DEPTH
            ),
        ));
        *nested_fallback = true;
        return Ok(crate::engine::raw_calldata_scalar(label, &inner_calldata));
    }

    let callee = match resolve_typed_nested_callee(message, params, container)? {
        Some(addr) => addr,
        None => {
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedCalldataDegraded,
                "nested calldata callee could not be resolved",
            ));
            *nested_fallback = true;
            return Ok(crate::engine::raw_calldata_scalar(label, &inner_calldata));
        }
    };

    let amount_bytes = resolve_typed_nested_amount(message, params, container)?;
    let spender_addr = resolve_typed_nested_spender(message, params, container)?;
    let chain_id = resolve_typed_nested_chain_id(message, params, container)?.ok_or_else(|| {
        Error::Descriptor(
            "EIP-712 container value @.chainId is required for nested calldata".to_string(),
        )
    })?;
    let selector_override = resolve_typed_nested_selector(message, params, container)?;
    let normalized_calldata = normalized_nested_calldata(&inner_calldata, selector_override);

    if normalized_calldata.len() < 4 {
        warnings.push(render_warning(
            RenderDiagnosticKind::NestedCalldataDegraded,
            "inner calldata too short",
        ));
        *nested_fallback = true;
        return Ok(crate::engine::raw_calldata_scalar(label, &inner_calldata));
    }

    let inner_descriptor = descriptors.iter().find(|rd| {
        rd.descriptor.context.deployments().iter().any(|dep| {
            dep.chain_id == chain_id && dep.address.to_lowercase() == callee.to_lowercase()
        })
    });

    let inner_descriptor = match inner_descriptor {
        Some(rd) => &rd.descriptor,
        None => {
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedDescriptorNotFound,
                "No matching descriptor for inner call",
            ));
            *nested_fallback = true;
            return Ok(crate::engine::raw_calldata_scalar(label, &inner_calldata));
        }
    };

    // Find matching signature + decode
    let (sig, _) = match crate::find_matching_signature(inner_descriptor, &normalized_calldata[..4])
    {
        Ok(result) => result,
        Err(_) => {
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedDescriptorNotFound,
                "No matching descriptor for inner call",
            ));
            *nested_fallback = true;
            return Ok(crate::engine::raw_calldata_scalar(label, &inner_calldata));
        }
    };

    let mut decoded = match crate::decoder::decode_calldata(&sig, &normalized_calldata) {
        Ok(d) => d,
        Err(_) => {
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedCalldataDegraded,
                "inner calldata could not be decoded",
            ));
            *nested_fallback = true;
            return Ok(crate::engine::raw_calldata_scalar(label, &inner_calldata));
        }
    };

    crate::inject_container_values(
        &mut decoded,
        chain_id,
        &callee,
        amount_bytes.as_deref(),
        spender_addr.as_deref(),
    );

    // Use engine's format pipeline for the inner call
    let mut inner_state = RenderState::default();
    let result = crate::engine::format_calldata(
        inner_descriptor,
        chain_id,
        &callee,
        &decoded,
        amount_bytes.as_deref(),
        data_provider,
        descriptors,
        &mut inner_state,
    )
    .await?;

    if inner_state.fallback_reason().is_some() {
        *nested_fallback = true;
    }
    warnings.extend(inner_state.diagnostics().iter().cloned());

    Ok(DisplayEntry::Nested {
        label: label.to_string(),
        intent: result.intent,
        owner: result.owner,
        entries: result.entries,
    })
}

/// Build a raw fallback DisplayModel for EIP-712 typed data when no format matches.
pub(crate) fn build_typed_raw_fallback(data: &TypedData) -> DisplayModel {
    let mut entries = Vec::new();

    // Use the primary type's field definitions to order entries if available
    if let Some(type_fields) = data.types.get(&data.primary_type) {
        for field in type_fields {
            let value = data
                .message
                .get(&field.name)
                .map(json_value_to_string)
                .unwrap_or_else(|| "<missing>".to_string());
            entries.push(DisplayEntry::Item(DisplayItem::new(
                field.name.clone(),
                value,
            )));
        }
    } else if let Some(obj) = data.message.as_object() {
        // Fallback: iterate message keys
        for (key, val) in obj {
            entries.push(DisplayEntry::Item(DisplayItem::new(
                key.clone(),
                json_value_to_string(val),
            )));
        }
    }

    DisplayModel {
        intent: data.primary_type.clone(),
        interpolated_intent: None,
        entries,
        owner: None,
        contract_name: None,
    }
}

pub(crate) fn find_typed_format<'a>(
    descriptor: &'a Descriptor,
    data: &TypedData,
) -> Result<&'a crate::types::display::DisplayFormat, Error> {
    match find_typed_format_optional(descriptor, data)? {
        Some(format) => Ok(format),
        None => Err(Error::Descriptor(format!(
            "no EIP-712 display format found for primaryType '{}' (expected encodeType '{}')",
            data.primary_type,
            encode_type_for_primary_type(data)?
        ))),
    }
}

pub(crate) fn find_typed_format_optional<'a>(
    descriptor: &'a Descriptor,
    data: &TypedData,
) -> Result<Option<&'a crate::types::display::DisplayFormat>, Error> {
    let encode_type = encode_type_for_primary_type(data)?;
    let expected_hash = keccak256(encode_type.as_bytes());
    let mut matches = Vec::new();

    for (key, format) in &descriptor.display.formats {
        if keccak256(key.as_bytes()) == expected_hash {
            matches.push((key, format));
        }
    }

    match matches.len() {
        1 => Ok(Some(matches[0].1)),
        0 => Ok(None),
        _ => {
            let keys: Vec<&str> = matches.iter().map(|(key, _)| key.as_str()).collect();
            Err(Error::Descriptor(format!(
                "multiple EIP-712 display formats match primaryType '{}': {}",
                data.primary_type,
                keys.join(", ")
            )))
        }
    }
}

pub(crate) fn encode_type_for_primary_type(data: &TypedData) -> Result<String, Error> {
    encode_type_for_type(&data.types, &data.primary_type)
}

pub(crate) fn encode_type_hash_hex_for_primary_type(data: &TypedData) -> Result<String, Error> {
    let encode_type = encode_type_for_primary_type(data)?;
    Ok(format_key_hash_hex(&encode_type))
}

pub(crate) fn format_key_hash_hex(key: &str) -> String {
    format!("0x{}", hex::encode(keccak256(key.as_bytes())))
}

pub(crate) fn encode_type_for_type(
    types: &HashMap<String, Vec<TypedDataField>>,
    type_name: &str,
) -> Result<String, Error> {
    let primary_fields = types.get(type_name).ok_or_else(|| {
        Error::Descriptor(format!("missing EIP-712 type definition '{}'", type_name))
    })?;

    let mut dependencies = std::collections::BTreeSet::new();
    collect_type_dependencies(type_name, types, &mut dependencies)?;
    dependencies.remove(type_name);

    let mut encoded = encode_type_segment(type_name, primary_fields);
    for dependency in dependencies {
        let fields = types.get(&dependency).ok_or_else(|| {
            Error::Descriptor(format!(
                "missing EIP-712 type definition for dependency '{}'",
                dependency
            ))
        })?;
        encoded.push_str(&encode_type_segment(&dependency, fields));
    }

    Ok(encoded)
}

fn collect_type_dependencies(
    type_name: &str,
    types: &HashMap<String, Vec<TypedDataField>>,
    dependencies: &mut std::collections::BTreeSet<String>,
) -> Result<(), Error> {
    let fields = types.get(type_name).ok_or_else(|| {
        Error::Descriptor(format!("missing EIP-712 type definition '{}'", type_name))
    })?;

    for field in fields {
        let base_type = base_type_name(&field.field_type);
        if types.contains_key(base_type) && dependencies.insert(base_type.to_string()) {
            collect_type_dependencies(base_type, types, dependencies)?;
        }
    }

    Ok(())
}

fn encode_type_segment(type_name: &str, fields: &[TypedDataField]) -> String {
    let fields = fields
        .iter()
        .map(|field| format!("{} {}", field.field_type, field.name))
        .collect::<Vec<_>>()
        .join(",");
    format!("{type_name}({fields})")
}

fn base_type_name(field_type: &str) -> &str {
    let mut base_type = field_type;
    while let Some(stripped) = base_type.strip_suffix(']') {
        if let Some(array_start) = stripped.rfind('[') {
            base_type = &stripped[..array_start];
        } else {
            break;
        }
    }
    base_type
}

pub(crate) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Resolve a path in EIP-712 message JSON (e.g., "recipient" or "details.amount").
///
/// Supports `[index]` and `[start:end]` slice notation.
fn resolve_typed_message_path(
    message: &serde_json::Value,
    path: &str,
) -> Option<serde_json::Value> {
    let mut current = message.clone();

    for segment in path.split('.') {
        // Handle array index: "items[0]" or "items[0:3]"
        if let Some(bracket) = segment.find('[') {
            let key = &segment[..bracket];
            let access = &segment[bracket..];

            if !key.is_empty() {
                current = current.get(key)?.clone();
            }

            current = apply_typed_access(&current, access)?;
        } else {
            current = current.get(segment)?.clone();
        }
    }

    Some(current)
}

#[allow(dead_code)]
pub(crate) fn resolve_typed_path(
    message: &serde_json::Value,
    path: &str,
    chain_id: u64,
    verifying_contract: Option<&str>,
) -> Option<serde_json::Value> {
    if let Some(message_path) = path.strip_prefix("#.") {
        return resolve_typed_message_path(message, message_path);
    }

    match path {
        "@.to" => verifying_contract.map(|addr| serde_json::Value::String(addr.to_string())),
        "@.chainId" => Some(serde_json::Value::from(chain_id)),
        "@.value" => Some(serde_json::Value::from(0u64)),
        "@.from" => None,
        _ if path.starts_with("@.") => None,
        _ => resolve_typed_message_path(message, path),
    }
}

fn resolve_typed_path_in_context(
    message: &serde_json::Value,
    path: &str,
    container: TypedContainerContext<'_>,
) -> Result<Option<serde_json::Value>, Error> {
    if let Some(message_path) = path.strip_prefix("#.") {
        return Ok(resolve_typed_message_path(message, message_path));
    }

    match path {
        "@.to" => container
            .verifying_contract
            .map(|addr| serde_json::Value::String(addr.to_string()))
            .map(Some)
            .ok_or_else(|| {
                Error::Descriptor(
                    "EIP-712 container value @.to is required but unavailable".to_string(),
                )
            }),
        "@.chainId" => container
            .chain_id
            .map(serde_json::Value::from)
            .map(Some)
            .ok_or_else(|| {
                Error::Descriptor(
                    "EIP-712 container value @.chainId is required but unavailable".to_string(),
                )
            }),
        "@.value" => Ok(Some(serde_json::Value::from(0u64))),
        "@.from" => container
            .from
            .map(|addr| serde_json::Value::String(addr.to_string()))
            .map(Some)
            .ok_or_else(|| {
                Error::Descriptor(
                    "EIP-712 container value @.from is required but unavailable".to_string(),
                )
            }),
        _ if path.starts_with("@.") => Err(Error::Descriptor(format!(
            "unsupported EIP-712 container path '{}'",
            path
        ))),
        _ => Ok(resolve_typed_message_path(message, path)),
    }
}

fn apply_typed_access(current: &serde_json::Value, segment: &str) -> Option<serde_json::Value> {
    match current {
        serde_json::Value::Array(items) => match apply_collection_access(items, segment)? {
            CollectionSelection::Item(item) => Some(item),
            CollectionSelection::Slice(slice) => Some(serde_json::Value::Array(slice)),
        },
        serde_json::Value::String(s) => {
            let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            let bytes = hex::decode(hex_str).ok()?;
            match apply_collection_access(&bytes, segment)? {
                CollectionSelection::Item(byte) => {
                    Some(serde_json::Value::String(format!("0x{:02x}", byte)))
                }
                CollectionSelection::Slice(slice) => Some(serde_json::Value::String(format!(
                    "0x{}",
                    hex::encode(slice)
                ))),
            }
        }
        _ => None,
    }
}

fn typed_visibility_context(label: &str, path: &str) -> String {
    if path.is_empty() {
        format!("field '{}'", label)
    } else {
        format!("field '{}' (path '{}')", label, path)
    }
}

fn check_typed_visibility(
    rule: &VisibleRule,
    value: &Option<serde_json::Value>,
    label: &str,
    path: &str,
) -> Result<bool, Error> {
    match rule {
        VisibleRule::Always => Ok(true),
        VisibleRule::Bool(b) => Ok(*b),
        VisibleRule::Named(literal) => Ok(matches!(
            literal,
            VisibleLiteral::Always | VisibleLiteral::Optional
        )),
        VisibleRule::Condition(cond) => {
            let Some(val) = value else {
                if cond.must_match.is_some() {
                    return Err(Error::Render(format!(
                        "{} uses visible.mustMatch but the value could not be resolved",
                        typed_visibility_context(label, path)
                    )));
                }
                return Ok(true);
            };

            if cond.hides_for_if_not_in(val) {
                return Ok(false);
            }
            if cond.must_match.is_some() {
                if cond.matches_must_match(val) {
                    return Ok(false);
                }
                return Err(Error::Render(format!(
                    "{} failed visible.mustMatch",
                    typed_visibility_context(label, path)
                )));
            }
            Ok(true)
        }
    }
}

pub(crate) fn coerce_typed_numeric_string(val: &serde_json::Value) -> Option<String> {
    coerce_unsigned_decimal_string_from_typed_value(val)
}

pub(crate) fn parse_typed_biguint_value(
    val: &serde_json::Value,
    format_name: &str,
) -> Result<BigUint, Error> {
    parse_unsigned_biguint_from_typed_value(val, format_name)
}

fn parse_typed_u64_value(val: &serde_json::Value, format_name: &str) -> Result<u64, Error> {
    let value = parse_typed_biguint_value(val, format_name)?;
    u64::try_from(&value)
        .map_err(|_| Error::Render(format!("{format_name} field does not fit into u64")))
}

fn parse_typed_i64_value(val: &serde_json::Value, format_name: &str) -> Result<i64, Error> {
    match val {
        serde_json::Value::Number(n) => {
            if let Some(value) = n.as_i64() {
                Ok(value)
            } else if let Some(value) = n.as_u64() {
                i64::try_from(value).map_err(|_| {
                    Error::Render(format!("{format_name} field does not fit into i64"))
                })
            } else {
                Err(Error::Render(format!(
                    "{format_name} field must be an integer"
                )))
            }
        }
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if let Ok(value) = trimmed.parse::<i64>() {
                Ok(value)
            } else if let Some(hex_str) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                let bytes = hex::decode(hex_str).map_err(|_| {
                    Error::Render(format!("{format_name} field must be an integer"))
                })?;
                let value = BigUint::from_bytes_be(&bytes);
                i64::try_from(&value).map_err(|_| {
                    Error::Render(format!("{format_name} field does not fit into i64"))
                })
            } else {
                let value = trimmed.parse::<BigUint>().map_err(|_| {
                    Error::Render(format!("{format_name} field must be an integer"))
                })?;
                i64::try_from(&value).map_err(|_| {
                    Error::Render(format!("{format_name} field does not fit into i64"))
                })
            }
        }
        _ => Err(Error::Render(format!(
            "{format_name} field must be an integer"
        ))),
    }
}

pub(crate) fn coerce_typed_address_string(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => {
            let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            let bytes = hex::decode(hex_str).ok()?;
            let addr = crate::engine::address_bytes_from_raw_bytes(&bytes)?;
            if bytes.len() == 20 && hex_str.len() == 40 {
                Some(s.clone())
            } else {
                Some(format!("0x{}", hex::encode(addr)))
            }
        }
        serde_json::Value::Number(n) => n.as_u64().map(|v| format!("0x{:040x}", v)),
        _ => None,
    }
}

/// EIP-55 checksum an address string for display, leaving non-addresses unchanged.
fn checksum_address_string(addr: &str) -> String {
    let Some(hex_str) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) else {
        return addr.to_string();
    };
    match hex::decode(hex_str)
        .ok()
        .and_then(|bytes| crate::engine::address_bytes_from_raw_bytes(&bytes))
    {
        Some(b) => crate::engine::eip55_checksum(&b),
        None => addr.to_string(),
    }
}

pub(crate) fn selector_from_typed_value(val: &serde_json::Value) -> Option<[u8; 4]> {
    match val {
        serde_json::Value::String(s) => {
            let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            let bytes = hex::decode(hex_str).ok()?;
            if bytes.len() < 4 {
                return None;
            }
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&bytes[..4]);
            Some(selector)
        }
        serde_json::Value::Number(_) => {
            let numeric = coerce_typed_numeric_string(val)?;
            let biguint = numeric.parse::<BigUint>().ok()?;
            let bytes = biguint.to_bytes_be();
            if bytes.len() > 32 || bytes.is_empty() {
                return None;
            }
            let mut padded = vec![0u8; 32usize.saturating_sub(bytes.len())];
            padded.extend_from_slice(&bytes);
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&padded[padded.len() - 4..]);
            Some(selector)
        }
        _ => None,
    }
}

fn chain_id_from_typed_value(val: &serde_json::Value) -> Option<u64> {
    let numeric = coerce_typed_numeric_string(val)?;
    numeric.parse::<u64>().ok()
}

fn uint_bytes_from_typed_value(val: &serde_json::Value) -> Option<Vec<u8>> {
    let numeric = coerce_typed_numeric_string(val)?;
    let biguint = numeric.parse::<BigUint>().ok()?;
    uint_bytes_from_biguint(&biguint, "amount").ok()
}

fn resolve_typed_map(
    descriptor: &Descriptor,
    message: &serde_json::Value,
    container: TypedContainerContext<'_>,
    map_ref: &str,
    val: &serde_json::Value,
) -> Result<Option<String>, Error> {
    let Some(map_def) = descriptor.metadata.maps.get(map_ref) else {
        return Ok(None);
    };

    let key = if let Some(ref key_path) = map_def.key_path {
        let Some(key_val) = resolve_typed_path_in_context(message, key_path, container)? else {
            return Ok(None);
        };
        json_value_to_string(&key_val)
    } else {
        json_value_to_string(val)
    };

    Ok(lookup_map_entry(descriptor, map_ref, &key))
}

fn resolve_typed_nested_callee(
    message: &serde_json::Value,
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
) -> Result<Option<String>, Error> {
    let Some(params) = params else {
        return Ok(None);
    };
    ensure_single_nested_param_source(
        params.callee.is_some(),
        params.callee_path.is_some(),
        "callee",
    )?;
    if let Some(callee) = params.callee.as_deref() {
        return parse_nested_address_param(callee, "callee").map(Some);
    }
    Ok(match params.callee_path.as_ref() {
        Some(path) => resolve_typed_path_in_context(message, path, container)?
            .as_ref()
            .and_then(coerce_typed_address_string),
        None => None,
    })
}

fn resolve_typed_nested_spender(
    message: &serde_json::Value,
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
) -> Result<Option<String>, Error> {
    let Some(params) = params else {
        return Ok(None);
    };
    ensure_single_nested_param_source(
        params.spender.is_some(),
        params.spender_path.is_some(),
        "spender",
    )?;
    if let Some(spender) = params.spender.as_deref() {
        return parse_nested_address_param(spender, "spender").map(Some);
    }
    Ok(match params.spender_path.as_ref() {
        Some(path) => resolve_typed_path_in_context(message, path, container)?
            .as_ref()
            .and_then(coerce_typed_address_string),
        None => None,
    })
}

fn resolve_typed_nested_amount(
    message: &serde_json::Value,
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(params) = params else {
        return Ok(None);
    };
    ensure_single_nested_param_source(
        params.amount.is_some(),
        params.amount_path.is_some(),
        "amount",
    )?;
    if let Some(amount) = params.amount.as_ref() {
        return parse_nested_amount_literal(amount, "amount").map(Some);
    }
    Ok(match params.amount_path.as_ref() {
        Some(path) => resolve_typed_path_in_context(message, path, container)?
            .as_ref()
            .and_then(uint_bytes_from_typed_value),
        None => None,
    })
}

fn resolve_typed_nested_chain_id(
    message: &serde_json::Value,
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
) -> Result<Option<u64>, Error> {
    let Some(params) = params else {
        return Ok(container.chain_id);
    };
    ensure_single_nested_param_source(
        params.chain_id.is_some(),
        params.chain_id_path.is_some(),
        "chainId",
    )?;
    if let Some(chain_id) = params.chain_id {
        return Ok(Some(chain_id));
    }
    Ok(match params.chain_id_path.as_ref() {
        Some(path) => resolve_typed_path_in_context(message, path, container)?
            .as_ref()
            .and_then(chain_id_from_typed_value),
        None => container.chain_id,
    })
}

fn resolve_typed_nested_selector(
    message: &serde_json::Value,
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
) -> Result<Option<[u8; 4]>, Error> {
    let Some(params) = params else {
        return Ok(None);
    };
    ensure_single_nested_param_source(
        params.selector.is_some(),
        params.selector_path.is_some(),
        "selector",
    )?;
    if let Some(selector) = params.selector.as_deref() {
        return parse_nested_selector_param(selector, "selector").map(Some);
    }
    Ok(match params.selector_path.as_ref() {
        Some(path) => resolve_typed_path_in_context(message, path, container)?
            .as_ref()
            .and_then(selector_from_typed_value),
        None => None,
    })
}

/// The ciphertext an encrypted typed-data field carries.
///
/// Handles are `bytes32`/`bytes` in practice, i.e. `0x` hex strings; a numeric
/// handle is accepted as its big-endian bytes. Anything else (bool, array,
/// object) cannot be a ciphertext.
fn typed_ciphertext_bytes(val: &serde_json::Value) -> Option<Vec<u8>> {
    let decimal = match val {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if let Some(hex_str) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                return hex::decode(hex_str).ok();
            }
            trimmed.to_string()
        }
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    decimal.parse::<BigUint>().ok().map(|n| n.to_bytes_be())
}

/// The value an encrypted typed-data field carries in the signing request,
/// 0x-hex, for [`DisplayItem::raw_encrypted_value`] — the typed twin of
/// `engine::raw_encrypted_value`. Normalized through `typed_ciphertext_bytes`, so
/// a handle authored as a decimal string is reported as hex.
fn typed_raw_encrypted_value(
    value: &Option<serde_json::Value>,
    params: Option<&FormatParams>,
) -> Option<String> {
    params.and_then(|p| p.encryption.as_ref())?;
    let bytes = typed_ciphertext_bytes(value.as_ref()?)?;
    Some(format!("0x{}", hex::encode(bytes)))
}

/// Build a typed-data value from a decrypted plaintext, in the shapes an EIP-712
/// message carries them: decimal strings for numbers, `0x` hex for addresses and
/// byte strings. The declared category drives this, never the bytes' shape.
fn typed_value_from_plaintext(kind: PlainKind, bytes: &[u8]) -> serde_json::Value {
    let string = |s: String| serde_json::Value::String(s);
    match kind {
        PlainKind::Uint => string(BigUint::from_bytes_be(bytes).to_string()),
        // Two's-complement word — the declared width is already baked in.
        PlainKind::Int => string(crate::engine::int_to_bigint(bytes).to_string()),
        PlainKind::Bool => serde_json::Value::Bool(bytes.iter().any(|&b| b != 0)),
        PlainKind::Address | PlainKind::Bytes => string(format!("0x{}", hex::encode(bytes))),
        PlainKind::String => string(String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// What an encrypted typed-data field renders from: the plaintext, or the text
/// standing in for it.
enum TypedPlaintext {
    Value(serde_json::Value),
    /// The field's `fallbackLabel` (or a generic placeholder) — never the
    /// ciphertext.
    Fallback(String),
}

/// Decrypt an encrypted typed-data field value, mirroring the calldata path: the
/// wallet is asked once per handle, the plaintext is re-read as the declared
/// `plaintextType`, and every recoverable failure degrades to the field's
/// fallback text with a diagnostic.
///
/// `Err` is a malformed annotation, fatal like any other descriptor error.
async fn decrypt_typed_value(
    val: &serde_json::Value,
    enc: &EncryptionParams,
    container: TypedContainerContext<'_>,
    data_provider: &dyn DataProvider,
    warnings: &mut RenderDiagnostics,
) -> Result<TypedPlaintext, Error> {
    let Some(ciphertext) = typed_ciphertext_bytes(val) else {
        warnings.push(render_warning(
            RenderDiagnosticKind::DecryptionFailed,
            format!(
                "encrypted field value '{}' is not a hex or numeric handle",
                json_value_to_string(val)
            ),
        ));
        return Ok(TypedPlaintext::Fallback(fallback_text(enc)));
    };

    // The contract the ciphertext is accessed through, EIP-55 checksummed like
    // calldata's `@.to`; absent when the domain declares no `verifyingContract`
    // or it is not a well-formed address.
    let contract_address = container
        .verifying_contract
        .map(|addr| serde_json::Value::String(addr.to_string()))
        .as_ref()
        .and_then(coerce_typed_address_string)
        .map(|addr| checksum_address_string(&addr));

    let outcome = container
        .decryption
        .resolve(
            data_provider,
            container.chain_id,
            contract_address.as_deref(),
            &ciphertext,
            enc,
            warnings,
        )
        .await?;

    Ok(match outcome {
        Decryption::Plaintext { kind, bytes } => {
            TypedPlaintext::Value(typed_value_from_plaintext(kind, &bytes))
        }
        Decryption::Fallback { text, .. } => TypedPlaintext::Fallback(text),
    })
}

/// Whether a typed-data field is visible, evaluating conditional rules against
/// the decrypted plaintext for encrypted fields — the calldata rule, see
/// `engine::is_field_visible` for why.
#[allow(clippy::too_many_arguments)]
async fn is_typed_field_visible(
    rule: &VisibleRule,
    value: &Option<serde_json::Value>,
    params: Option<&FormatParams>,
    label: &str,
    path: &str,
    container: TypedContainerContext<'_>,
    data_provider: &dyn DataProvider,
    warnings: &mut RenderDiagnostics,
) -> Result<bool, Error> {
    let Some(enc) = params.and_then(|p| p.encryption.as_ref()) else {
        return check_typed_visibility(rule, value, label, path);
    };
    validate_annotation(enc)?;

    let plaintext = match (rule, value) {
        (VisibleRule::Condition(_), Some(val)) => {
            match decrypt_typed_value(val, enc, container, data_provider, warnings).await? {
                TypedPlaintext::Value(plaintext) => Some(plaintext),
                TypedPlaintext::Fallback(_) => None,
            }
        }
        _ => return check_typed_visibility(rule, value, label, path),
    };
    check_typed_visibility(rule, &plaintext, label, path)
}

#[allow(clippy::too_many_arguments)]
async fn format_typed_value(
    descriptor: &Descriptor,
    value: &Option<serde_json::Value>,
    format: Option<&FieldFormat>,
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
    message: &serde_json::Value,
    item_scope: Option<&serde_json::Value>,
    data_provider: &dyn DataProvider,
    warnings: &mut RenderDiagnostics,
) -> Result<String, Error> {
    let Some(val) = value else {
        return Ok("<unresolved>".to_string());
    };

    // Encryption (ERC-7730 `encryption`): decrypt via the wallet, then render the
    // plaintext with the field's regular format — the same path calldata takes,
    // using the typed container's chainId and verifyingContract. When decryption
    // is unavailable the field renders its `fallbackLabel`.
    let decrypted_owned;
    if let Some(enc) = params.and_then(|p| p.encryption.as_ref()) {
        match decrypt_typed_value(val, enc, container, data_provider, warnings).await? {
            TypedPlaintext::Value(plaintext) => decrypted_owned = Some(plaintext),
            TypedPlaintext::Fallback(text) => return Ok(text),
        }
    } else {
        decrypted_owned = None;
    }
    // From here on `val` is the decrypted plaintext when decryption succeeded.
    let val: &serde_json::Value = decrypted_owned.as_ref().unwrap_or(val);

    // Map reference
    if let Some(params) = params {
        if let Some(ref map_ref) = params.map_reference {
            if let Some(mapped) = resolve_typed_map(descriptor, message, container, map_ref, val)? {
                return Ok(mapped);
            }
        }
    }

    let Some(fmt) = format else {
        return Ok(json_value_to_string(val));
    };

    match fmt {
        FieldFormat::Address => Ok(coerce_typed_address_string(val)
            .map(|a| checksum_address_string(&a))
            .unwrap_or_else(|| json_value_to_string(val))),
        FieldFormat::AddressName | FieldFormat::InteroperableAddressName => {
            let addr =
                coerce_typed_address_string(val).unwrap_or_else(|| json_value_to_string(val));

            // Check senderAddress
            if let Some(params) = params {
                if let Some(ref sender) = params.sender_address {
                    let sender_addrs = match sender {
                        crate::types::display::SenderAddress::Single(s) => vec![s.as_str()],
                        crate::types::display::SenderAddress::Multiple(v) => {
                            v.iter().map(|s| s.as_str()).collect()
                        }
                    };
                    for sender_ref in &sender_addrs {
                        let resolved =
                            if sender_ref.starts_with("@.") || sender_ref.starts_with('#') {
                                resolve_typed_path_in_context(message, sender_ref, container)?
                                    .and_then(|v| match v {
                                        serde_json::Value::String(s) => Some(s),
                                        _ => None,
                                    })
                            } else {
                                Some(resolve_metadata_constant_str(descriptor, sender_ref))
                            };
                        if let Some(resolved_addr) = resolved {
                            if resolved_addr.to_lowercase() == addr.to_lowercase() {
                                return Ok("Sender".to_string());
                            }
                        }
                    }
                }
            }

            // Determine allowed sources
            let sources = params.and_then(|p| p.sources.as_ref());
            let local_allowed = sources
                .map(|s| s.iter().any(|src| src == "local"))
                .unwrap_or(true);
            let ens_allowed = sources
                .map(|s| s.iter().any(|src| src == "ens"))
                .unwrap_or(true);
            let chain_id = container.chain_id.ok_or_else(|| {
                Error::Descriptor(
                    "EIP-712 container value @.chainId is required for addressName".to_string(),
                )
            })?;

            if local_allowed {
                if let Some(name) = data_provider
                    .resolve_local_name(&addr, chain_id, params.and_then(|p| p.types.as_deref()))
                    .await
                {
                    return Ok(name);
                }
            }
            if ens_allowed {
                if let Some(name) = data_provider
                    .resolve_ens_name(&addr, chain_id, params.and_then(|p| p.types.as_deref()))
                    .await
                {
                    return Ok(name);
                }
            }
            Ok(checksum_address_string(&addr))
        }
        FieldFormat::TokenAmount => {
            let amount = parse_typed_biguint_value(val, "tokenAmount")?;

            let lookup_chain = resolve_typed_chain_id(params, container, message)?;

            let token_meta = if let Some(params) = params {
                if let Some(ref token_path) = params.token_path {
                    let token_addr = resolve_typed_param_path_in_context(
                        message, token_path, container, item_scope,
                    )?;
                    let addr_str = token_addr.as_ref().and_then(coerce_typed_address_string);
                    if let Some(addr) = addr_str {
                        if let Some(ref native) = params.native_currency_address {
                            if native.matches(&addr, &descriptor.metadata.constants) {
                                Some(native_token_meta(lookup_chain))
                            } else {
                                data_provider.resolve_token(lookup_chain, &addr).await
                            }
                        } else {
                            data_provider.resolve_token(lookup_chain, &addr).await
                        }
                    } else {
                        None
                    }
                } else if let Some(ref token_ref) = params.token {
                    let addr = resolve_metadata_constant_str(descriptor, token_ref);
                    if let Some(ref native) = params.native_currency_address {
                        if native.matches(&addr, &descriptor.metadata.constants) {
                            Some(native_token_meta(lookup_chain))
                        } else {
                            data_provider.resolve_token(lookup_chain, &addr).await
                        }
                    } else {
                        data_provider.resolve_token(lookup_chain, &addr).await
                    }
                } else {
                    None
                }
            } else {
                None
            };

            Ok(format_token_amount_output(
                descriptor,
                &amount,
                params,
                token_meta.as_ref(),
            ))
        }
        FieldFormat::Date => {
            if params.and_then(|p| p.encoding.as_deref()) == Some("blockheight") {
                let chain_id = container.chain_id.ok_or_else(|| {
                    Error::Descriptor(
                        "EIP-712 container value @.chainId is required for blockheight dates"
                            .to_string(),
                    )
                })?;
                let block_number = parse_typed_u64_value(val, "date")?;
                format_blockheight_timestamp(data_provider, chain_id, block_number).await
            } else {
                let ts = parse_typed_i64_value(val, "date")?;
                format_timestamp(ts)
            }
        }
        FieldFormat::Enum => {
            let raw = coerce_typed_numeric_string(val).unwrap_or_else(|| json_value_to_string(val));
            if let Some(params) = params {
                if let Some(ref enum_path) = params.enum_path {
                    if let Some(enum_def) = descriptor.metadata.enums.get(enum_path) {
                        if let Some(label) = enum_def.get(&raw) {
                            return Ok(label.clone());
                        }
                    }
                }
                // $ref path (v2): "$.metadata.enums.interestRateMode"
                if let Some(ref ref_path) = params.ref_path {
                    if let Some(enum_name) = ref_path.strip_prefix("$.metadata.enums.") {
                        if let Some(enum_def) = descriptor.metadata.enums.get(enum_name) {
                            if let Some(label) = enum_def.get(&raw) {
                                return Ok(label.clone());
                            }
                        }
                    }
                }
            }
            Ok(raw)
        }
        FieldFormat::Number => Ok(coerce_unsigned_decimal_string_from_typed_value(val)
            .unwrap_or_else(|| json_value_to_string(val))),
        FieldFormat::TokenTicker => {
            let lookup_chain = resolve_typed_chain_id(params, container, message)?;
            let addr =
                coerce_typed_address_string(val).unwrap_or_else(|| json_value_to_string(val));
            if let Some(meta) = data_provider.resolve_token(lookup_chain, &addr).await {
                Ok(meta.symbol)
            } else {
                warnings.push(render_warning(
                    RenderDiagnosticKind::TokenTickerNotFound,
                    "token ticker not found",
                ));
                Ok(addr)
            }
        }
        FieldFormat::ChainId => {
            let cid = parse_typed_u64_value(val, "chainId")?;
            Ok(chain_name(cid))
        }
        // No EIP-712 type is known here, so a 20-byte hex value under `raw` is
        // treated as an address and checksummed (parity with the calldata Address
        // path); a genuine `bytes20` raw field would be mis-cased.
        FieldFormat::Raw => Ok(match val {
            serde_json::Value::String(s)
                if s.len() == 42
                    && (s.starts_with("0x") || s.starts_with("0X"))
                    && s[2..].chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                checksum_address_string(s)
            }
            _ => json_value_to_string(val),
        }),
        FieldFormat::Amount => match coerce_unsigned_biguint_from_typed_value(val) {
            Some(n) => {
                // Per ERC-7730 the `amount` format is a native-currency amount.
                let chain_id = resolve_typed_chain_id(params, container, message)?;
                let meta = native_token_meta(chain_id);
                Ok(format!(
                    "{} {}",
                    format_with_decimals(&n, meta.decimals),
                    meta.symbol
                ))
            }
            None => Ok(json_value_to_string(val)),
        },
        FieldFormat::Duration => {
            let secs = parse_typed_u64_value(val, "duration")?;
            Ok(format_duration_seconds(secs))
        }
        FieldFormat::Unit => {
            let amount = parse_unsigned_biguint_from_typed_value(val, "unit")?;
            let base = params
                .and_then(|p| p.base.as_deref())
                .map(|b| resolve_metadata_constant_str(descriptor, b))
                .unwrap_or_default();
            Ok(format_unit_biguint(&amount, &base, params))
        }
        FieldFormat::NftName => {
            let token_id = json_value_to_string(val);
            let collection_addr = match params {
                Some(p) => {
                    if let Some(ref cpath) = p.collection_path {
                        match resolve_typed_path_in_context(message, cpath, container)? {
                            Some(serde_json::Value::String(addr)) => Some(addr),
                            _ => p.collection.clone(),
                        }
                    } else {
                        p.collection.clone()
                    }
                }
                None => None,
            };
            if let Some(ref addr) = collection_addr {
                let chain_id = container.chain_id.ok_or_else(|| {
                    Error::Descriptor(
                        "EIP-712 container value @.chainId is required for nftName".to_string(),
                    )
                })?;
                if let Some(name) = data_provider
                    .resolve_nft_collection_name(addr, chain_id)
                    .await
                {
                    return Ok(format!("{} #{}", name, token_id));
                }
            }
            Ok(format!("#{}", token_id))
        }
        FieldFormat::Calldata => {
            // Should not reach here — calldata is intercepted in render_typed_fields
            warnings.push(render_warning(
                RenderDiagnosticKind::GenericRenderWarning,
                "calldata format should be handled separately",
            ));
            Ok(json_value_to_string(val))
        }
    }
}

fn resolve_typed_chain_id(
    params: Option<&FormatParams>,
    container: TypedContainerContext<'_>,
    message: &serde_json::Value,
) -> Result<u64, Error> {
    if let Some(params) = params {
        if let Some(cid) = params.chain_id {
            return Ok(cid);
        }
        if let Some(ref path) = params.chain_id_path {
            if let Some(val) = resolve_typed_path_in_context(message, path, container)? {
                return parse_typed_u64_value(&val, "chainId");
            }
        }
    }
    container.chain_id.ok_or_else(|| {
        Error::Descriptor(
            "EIP-712 container value @.chainId is required but unavailable".to_string(),
        )
    })
}

fn json_value_to_string(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

async fn interpolate_typed_intent(
    template: &str,
    descriptor: &Descriptor,
    message: &serde_json::Value,
    container: TypedContainerContext<'_>,
    fields: &[DisplayField],
    excluded: &[String],
    data_provider: &dyn DataProvider,
) -> Result<String, Error> {
    // Pre-process: replace {{ and }} with sentinels
    const OPEN_SENTINEL: &str = "\x00OPEN_BRACE\x00";
    const CLOSE_SENTINEL: &str = "\x00CLOSE_BRACE\x00";
    let mut result = template
        .replace("{{", OPEN_SENTINEL)
        .replace("}}", CLOSE_SENTINEL);

    // First pass: replace ${path} patterns (v1)
    while let Some(start) = result.find("${") {
        let end = match result[start..].find('}') {
            Some(e) => start + e,
            None => break,
        };
        let path = &result[start + 2..end];
        let replacement = resolve_and_format_typed_interpolation(
            descriptor,
            message,
            container,
            fields,
            path,
            excluded,
            data_provider,
        )
        .await?;
        result.replace_range(start..=end, &replacement);
    }

    // Second pass: replace {name} patterns (v2)
    let mut pos = 0;
    while pos < result.len() {
        if let Some(rel_start) = result[pos..].find('{') {
            let start = pos + rel_start;
            if start > 0 && result.as_bytes()[start - 1] == b'$' {
                pos = start + 1;
                continue;
            }
            let end = match result[start..].find('}') {
                Some(e) => start + e,
                None => break,
            };
            let path = result[start + 1..end].to_string();
            let replacement = resolve_and_format_typed_interpolation(
                descriptor,
                message,
                container,
                fields,
                &path,
                excluded,
                data_provider,
            )
            .await?;
            result.replace_range(start..=end, &replacement);
            pos = start + replacement.len();
        } else {
            break;
        }
    }

    // Post-process: restore escaped braces
    let result = result
        .replace(OPEN_SENTINEL, "{")
        .replace(CLOSE_SENTINEL, "}");

    Ok(result)
}

async fn resolve_and_format_typed_interpolation(
    descriptor: &Descriptor,
    message: &serde_json::Value,
    container: TypedContainerContext<'_>,
    fields: &[DisplayField],
    path: &str,
    excluded: &[String],
    data_provider: &dyn DataProvider,
) -> Result<String, Error> {
    let field = resolve_interpolation_field_spec(fields, excluded, path)?;

    // Array-iteration paths (`.[]`) format each element like field rendering and
    // join with " and " (parity with the calldata path).
    if let Some((base, rest)) = crate::engine::split_array_iter_path(field.path) {
        if let Some(serde_json::Value::Array(items)) =
            resolve_typed_path_in_context(message, base, container)?
        {
            if !items.is_empty() {
                let mut parts = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    let val = if rest.is_empty() {
                        Some(item.clone())
                    } else {
                        resolve_typed_path_in_context(item, rest, container)?
                    };
                    // Flat array path: rewrite element-relative param paths
                    // (`x.[].token`) to the concrete index and resolve against the
                    // root, matching the calldata interpolation path.
                    let item_params = crate::engine::index_array_params(field.params, i);
                    let mut warnings = Vec::new();
                    parts.push(
                        format_typed_value(
                            descriptor,
                            &val,
                            field.format,
                            item_params.as_ref(),
                            container,
                            message,
                            None,
                            data_provider,
                            &mut warnings,
                        )
                        .await?,
                    );
                }
                return Ok(parts.join(" and "));
            }
        }
    }

    let value =
        resolve_typed_path_in_context(message, field.path, container)?.ok_or_else(|| {
            Error::Descriptor(format!(
                "interpolatedIntent path '{}' could not be resolved from typed data",
                path
            ))
        })?;

    let mut warnings = Vec::new();
    format_typed_value(
        descriptor,
        &Some(value),
        field.format,
        field.params,
        container,
        message,
        None,
        data_provider,
        &mut warnings,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{StaticTokenSource, TokenMeta};

    #[test]
    fn test_resolve_typed_path() {
        let message = serde_json::json!({
            "recipient": "0xabc",
            "details": {
                "amount": "1000",
                "token": "0xdef"
            }
        });

        assert_eq!(
            resolve_typed_message_path(&message, "recipient"),
            Some(serde_json::json!("0xabc"))
        );
        assert_eq!(
            resolve_typed_message_path(&message, "details.amount"),
            Some(serde_json::json!("1000"))
        );
        assert_eq!(resolve_typed_message_path(&message, "nonexistent"), None);
    }

    #[test]
    fn test_resolve_typed_path_hex_slices() {
        let message = serde_json::json!({
            "hookData": "0x636374702d666f72776172640000000000000000000000000000000000000018f0a063a21be62b709937ca2a808594b662fe41e600000000",
            "packed": "0x000000000000000000000000b21d281dedb17ae5b501f6aa8256fe38c4e45757"
        });

        assert_eq!(
            resolve_typed_message_path(&message, "hookData.[32:52]"),
            Some(serde_json::json!(
                "0xf0a063a21be62b709937ca2a808594b662fe41e6"
            ))
        );
        assert_eq!(
            resolve_typed_message_path(&message, "hookData.[52:53]"),
            Some(serde_json::json!("0x00"))
        );
        assert_eq!(
            resolve_typed_message_path(&message, "packed.[-20:]"),
            Some(serde_json::json!(
                "0xb21d281dedb17ae5b501f6aa8256fe38c4e45757"
            ))
        );
    }

    #[test]
    fn test_resolve_typed_path_container_values() {
        let message = serde_json::json!({
            "to": "0xa95d9c1f655341597c94393fddc30cf3c08e4fce"
        });

        assert_eq!(
            resolve_typed_path(
                &message,
                "to",
                42161,
                Some("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            ),
            Some(serde_json::json!(
                "0xa95d9c1f655341597c94393fddc30cf3c08e4fce"
            ))
        );
        assert_eq!(
            resolve_typed_path(
                &message,
                "@.to",
                42161,
                Some("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            ),
            Some(serde_json::json!(
                "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
            ))
        );
        assert_eq!(
            resolve_typed_path(
                &message,
                "@.chainId",
                42161,
                Some("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            ),
            Some(serde_json::json!(42161))
        );
        assert_eq!(
            resolve_typed_path(
                &message,
                "@.value",
                42161,
                Some("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            ),
            Some(serde_json::json!(0))
        );
        assert_eq!(
            resolve_typed_path(
                &message,
                "@.from",
                42161,
                Some("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            ),
            None
        );
        assert_eq!(
            resolve_typed_path(
                &message,
                "@.verifyingContract",
                42161,
                Some("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            ),
            None
        );
    }

    #[test]
    fn test_json_value_to_string() {
        assert_eq!(json_value_to_string(&serde_json::json!("hello")), "hello");
        assert_eq!(json_value_to_string(&serde_json::json!(42)), "42");
        assert_eq!(json_value_to_string(&serde_json::json!(true)), "true");
    }

    #[tokio::test]
    async fn test_typed_byte_slice_formatters() {
        let descriptor_json = r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {
                "owner": "test",
                "enums": { "dex": { "0": "Perp" } },
                "constants": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "SliceTest(bytes hookData,bytes32 tokenWord,uint256 amount)": {
                        "intent": "Slice test",
                        "fields": [
                            {"path": "hookData.[32:52]", "label": "Recipient", "format": "addressName"},
                            {"path": "hookData.[52:53]", "label": "Dex", "format": "enum", "params": {"$ref": "$.metadata.enums.dex"}},
                            {"path": "amount", "label": "Amount", "format": "tokenAmount", "params": {"tokenPath": "tokenWord.[-20:]"}}
                        ]
                    }
                }
            }
        }"#;

        let typed_data: TypedData = serde_json::from_value(serde_json::json!({
            "types": {
                "EIP712Domain": [],
                "SliceTest": [
                    {"name": "hookData", "type": "bytes"},
                    {"name": "tokenWord", "type": "bytes32"},
                    {"name": "amount", "type": "uint256"}
                ]
            },
            "primaryType": "SliceTest",
            "domain": {"chainId": 1, "verifyingContract": "0xabc"},
            "message": {
                "hookData": "0x636374702d666f72776172640000000000000000000000000000000000000018f0a063a21be62b709937ca2a808594b662fe41e600000000",
                "tokenWord": "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "amount": "1500000"
            }
        }))
        .unwrap();

        let descriptor = Descriptor::from_json(descriptor_json).unwrap();
        let mut tokens = StaticTokenSource::new();
        tokens.insert(
            1,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            TokenMeta {
                symbol: "USDC".to_string(),
                decimals: 6,
                name: "USD Coin".to_string(),
            },
        );

        let result = format_typed_data(&descriptor, &typed_data, &tokens, &[])
            .await
            .unwrap();

        match &result.entries[0] {
            DisplayEntry::Item(item) => {
                assert_eq!(item.label, "Recipient");
                assert_eq!(item.value, "0xF0A063A21Be62B709937Ca2a808594b662fE41E6");
            }
            _ => panic!("expected Item"),
        }
        match &result.entries[1] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "Perp"),
            _ => panic!("expected Item"),
        }
        match &result.entries[2] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "1.5 USDC"),
            _ => panic!("expected Item"),
        }
    }

    #[tokio::test]
    async fn test_typed_byte_slice_numeric_formatters_match_calldata_semantics() {
        let descriptor_json = r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {
                "owner": "test",
                "enums": {},
                "constants": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "SliceTest(bytes32 tokenWord,bytes32 amountWord)": {
                        "intent": "Slice test",
                        "fields": [
                            {"path": "amountWord.[-2:]", "label": "Token Amount", "format": "tokenAmount", "params": {"tokenPath": "tokenWord.[-20:]"}},
                            {"path": "amountWord.[-2:]", "label": "Number", "format": "number"},
                            {"path": "amountWord.[-2:]", "label": "Amount", "format": "amount"},
                            {"path": "amountWord.[-2:]", "label": "Unit", "format": "unit", "params": {"base": "bps"}}
                        ]
                    }
                }
            }
        }"#;

        let typed_data: TypedData = serde_json::from_value(serde_json::json!({
            "types": {
                "EIP712Domain": [],
                "SliceTest": [
                    {"name": "tokenWord", "type": "bytes32"},
                    {"name": "amountWord", "type": "bytes32"}
                ]
            },
            "primaryType": "SliceTest",
            "domain": {"chainId": 1, "verifyingContract": "0xabc"},
            "message": {
                "tokenWord": "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "amountWord": "0x00000000000000000000000000000000000000000000000000000000000001f4"
            }
        }))
        .unwrap();

        let descriptor = Descriptor::from_json(descriptor_json).unwrap();
        let mut tokens = StaticTokenSource::new();
        tokens.insert(
            1,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            TokenMeta {
                symbol: "USDC".to_string(),
                decimals: 6,
                name: "USD Coin".to_string(),
            },
        );

        let result = format_typed_data(&descriptor, &typed_data, &tokens, &[])
            .await
            .unwrap();

        match &result.entries[0] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "0.0005 USDC"),
            _ => panic!("expected Item"),
        }
        match &result.entries[1] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "500"),
            _ => panic!("expected Item"),
        }
        match &result.entries[2] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "0.0000000000000005 ETH"),
            _ => panic!("expected Item"),
        }
        match &result.entries[3] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "500bps"),
            _ => panic!("expected Item"),
        }
    }

    #[tokio::test]
    async fn test_receive_with_authorization_token_amount_uses_container_to() {
        let descriptor_json = r#"{
            "$schema": "../../specs/erc7730-v1.schema.json",
            "context": {
                "eip712": {
                    "domain": { "name": "USD Coin", "version": "2" },
                    "deployments": [
                        { "chainId": 42161, "address": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831" }
                    ],
                    "schemas": [
                        {
                            "primaryType": "ReceiveWithAuthorization",
                            "types": {
                                "EIP712Domain": [
                                    { "name": "name", "type": "string" },
                                    { "name": "version", "type": "string" },
                                    { "name": "chainId", "type": "uint256" },
                                    { "name": "verifyingContract", "type": "address" }
                                ],
                                "ReceiveWithAuthorization": [
                                    { "name": "from", "type": "address" },
                                    { "name": "to", "type": "address" },
                                    { "name": "value", "type": "uint256" },
                                    { "name": "validAfter", "type": "uint256" },
                                    { "name": "validBefore", "type": "uint256" },
                                    { "name": "nonce", "type": "bytes32" }
                                ]
                            }
                        }
                    ]
                }
            },
            "metadata": {
                "owner": "Circle",
                "info": { "legalName": "Circle Internet Financial", "url": "https://www.circle.com/" },
                "enums": {},
                "constants": {},
                "maps": {}
            },
            "display": {
                "formats": {
                    "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)": {
                        "intent": "Authorize USDC transfer",
                        "interpolatedIntent": "Authorize on {@.chainId}",
                        "fields": [
                            { "path": "from", "label": "From", "format": "addressName", "params": { "types": ["wallet"], "sources": ["local", "ens"] } },
                            { "path": "to", "label": "To", "format": "addressName", "params": { "types": ["eoa", "contract"], "sources": ["local", "ens"] } },
                            { "path": "value", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "@.to" } },
                            { "path": "@.chainId", "label": "Chain ID", "visible": "never" },
                            { "path": "validAfter", "label": "Valid after", "format": "date", "params": { "encoding": "timestamp" } },
                            { "path": "validBefore", "label": "Valid before", "format": "date", "params": { "encoding": "timestamp" } }
                        ],
                        "required": ["from", "to", "value"],
                        "excluded": ["nonce"]
                    }
                }
            }
        }"#;

        let typed_data: TypedData = serde_json::from_value(serde_json::json!({
            "domain": {
                "name": "USD Coin",
                "version": "2",
                "chainId": 42161,
                "verifyingContract": "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
            },
            "message": {
                "from": "0xbf01daf454dce008d3e2bfd47d5e186f71477253",
                "to": "0xa95d9c1f655341597c94393fddc30cf3c08e4fce",
                "value": "6050000",
                "validAfter": 1774534342,
                "validBefore": 1774538002,
                "nonce": "0x9048fcc0671336730dda26a2a19a8ccdb2a6b7da00eeae556dd7f10c8a8d3a16"
            },
            "primaryType": "ReceiveWithAuthorization",
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "ReceiveWithAuthorization": [
                    { "name": "from", "type": "address" },
                    { "name": "to", "type": "address" },
                    { "name": "value", "type": "uint256" },
                    { "name": "validAfter", "type": "uint256" },
                    { "name": "validBefore", "type": "uint256" },
                    { "name": "nonce", "type": "bytes32" }
                ]
            }
        }))
        .unwrap();

        let descriptor = Descriptor::from_json(descriptor_json).unwrap();
        let mut tokens = StaticTokenSource::new();
        tokens.insert(
            42161,
            "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
            TokenMeta {
                symbol: "USDC".to_string(),
                decimals: 6,
                name: "USD Coin".to_string(),
            },
        );

        let result = format_typed_data(&descriptor, &typed_data, &tokens, &[])
            .await
            .unwrap();

        assert_eq!(result.intent, "Authorize USDC transfer");
        assert_eq!(
            result.interpolated_intent.as_deref(),
            Some("Authorize on 42161")
        );
        match &result.entries[2] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "6.05 USDC"),
            _ => panic!("expected Item"),
        }
    }

    #[tokio::test]
    async fn test_receive_with_authorization_token_amount_graceful_degrades_without_metadata() {
        let typed_data: TypedData = serde_json::from_value(serde_json::json!({
            "domain": {
                "chainId": 42161,
                "verifyingContract": "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
            },
            "message": {
                "value": "6050000"
            },
            "primaryType": "ReceiveWithAuthorization",
            "types": {
                "EIP712Domain": [],
                "ReceiveWithAuthorization": [
                    { "name": "value", "type": "uint256" }
                ]
            }
        }))
        .unwrap();

        let provider = crate::provider::EmptyDataProvider;
        let result = crate::format_typed_data(&[], &typed_data, &provider)
            .await
            .unwrap();

        match &result.entries[0] {
            DisplayEntry::Item(item) => assert_eq!(item.value, "6050000"),
            _ => panic!("expected Item"),
        }
    }

    #[tokio::test]
    async fn test_permit_graceful_fallback() {
        // Real USDC Permit typed data from wallet — no descriptor format for "Permit"
        let typed_data_json = r#"{
            "types": {
                "EIP712Domain": [
                    {"name":"name","type":"string"},
                    {"name":"version","type":"string"},
                    {"name":"chainId","type":"uint256"},
                    {"name":"verifyingContract","type":"address"}
                ],
                "Permit": [
                    {"name":"owner","type":"address"},
                    {"name":"spender","type":"address"},
                    {"name":"value","type":"uint256"},
                    {"name":"nonce","type":"uint256"},
                    {"name":"deadline","type":"uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            },
            "message": {
                "owner": "0xbf01daf454dce008d3e2bfd47d5e186f71477253",
                "spender": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
                "value": "100000",
                "nonce": 0,
                "deadline": "1773156895"
            }
        }"#;

        let typed_data: TypedData = serde_json::from_str(typed_data_json).unwrap();

        let provider = crate::provider::EmptyDataProvider;

        let result = crate::format_typed_data(&[], &typed_data, &provider)
            .await
            .unwrap();

        assert_eq!(result.intent, "Permit");
        assert_eq!(
            result.fallback_reason(),
            Some(&crate::FallbackReason::DescriptorNotFound)
        );
        assert!(
            result.diagnostics().iter().any(|diagnostic| diagnostic
                .message
                .contains("no typed-data descriptor matched")),
            "expected descriptor-not-found diagnostic"
        );

        // Should have all 5 fields from the Permit type, in order
        assert_eq!(result.entries.len(), 5);

        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "owner");
            assert_eq!(item.value, "0xbf01daf454dce008d3e2bfd47d5e186f71477253");
        } else {
            panic!("expected Item");
        }

        if let DisplayEntry::Item(ref item) = result.entries[1] {
            assert_eq!(item.label, "spender");
            assert_eq!(item.value, "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2");
        } else {
            panic!("expected Item");
        }

        if let DisplayEntry::Item(ref item) = result.entries[2] {
            assert_eq!(item.label, "value");
            assert_eq!(item.value, "100000");
        } else {
            panic!("expected Item");
        }

        if let DisplayEntry::Item(ref item) = result.entries[4] {
            assert_eq!(item.label, "deadline");
            assert_eq!(item.value, "1773156895");
        } else {
            panic!("expected Item");
        }
    }
}
