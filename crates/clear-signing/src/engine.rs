//! Formatting pipeline: resolves display fields, formats decoded values,
//! and produces a [`DisplayModel`] with labeled entries for wallet UIs.

use std::future::Future;
use std::pin::Pin;

use num_bigint::{BigInt, BigUint, Sign};

use crate::decoder::{ArgumentValue, DecodedArguments};
use crate::encryption::{validate_annotation, Decryption, DecryptionCache, PlainKind};
use crate::error::Error;
use crate::outcome::{render_warning, FormatDiagnostic, RenderDiagnosticKind, RenderState};
use crate::path::{apply_collection_access, CollectionSelection};
use crate::provider::DataProvider;
use crate::render_shared::{
    chain_name, coerce_unsigned_biguint_from_argument_value,
    coerce_unsigned_decimal_string_from_argument_value, format_blockheight_timestamp,
    format_duration_seconds, format_timestamp, format_token_amount_output, format_unit_biguint,
    format_with_decimals, is_excluded_path, lookup_map_entry, native_token_meta,
    resolve_interpolation_field_spec, resolve_metadata_constant_str,
};
use crate::resolver::ResolvedDescriptor;
use crate::types::descriptor::Descriptor;
use crate::types::display::{
    DisplayField, DisplayFormat, EncryptionParams, FieldFormat, FieldGroup, FormatParams,
    Iteration, SenderAddress, UintLiteral, VisibleLiteral, VisibleRule,
};

/// Maximum recursion depth for nested calldata formatting.
const MAX_CALLDATA_DEPTH: u8 = 3;

/// Output model for clear signing display.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisplayModel {
    pub intent: String,
    pub interpolated_intent: Option<String>,
    pub entries: Vec<DisplayEntry>,
    /// Owner of the descriptor that produced this model (from `metadata.owner`).
    pub owner: Option<String>,
    pub contract_name: Option<String>,
}

/// A display entry — either a flat item, a group of items, or a nested calldata call.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, serde::Serialize)]
pub enum DisplayEntry {
    Item(DisplayItem),
    Group {
        label: String,
        iteration: GroupIteration,
        items: Vec<DisplayItem>,
    },
    Nested {
        label: String,
        intent: String,
        /// Owner string for the inner call (the inner descriptor's `metadata.owner`),
        /// when a matching descriptor was found. `None` for raw/fallback frames where
        /// no inner descriptor matched.
        owner: Option<String>,
        entries: Vec<DisplayEntry>,
    },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, serde::Serialize)]
pub enum GroupIteration {
    Sequential,
    Bundled,
}

/// A single label+value pair for display.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisplayItem {
    pub label: String,
    pub value: String,
    /// For a field carrying an ERC-7730 `encryption` annotation, its value as it
    /// appears in the signing request — 0x-hex, the ciphertext itself or a
    /// pointer to it — before decryption.
    ///
    /// Set whether or not decryption succeeded. When it did not, `value` is the
    /// descriptor's `fallbackLabel` (or a generic placeholder) and a
    /// `decryption_failed` diagnostic is recorded; the spec RECOMMENDS wallets
    /// show this raw value — fully or truncated — next to that placeholder, so
    /// the user can tell a real value is present but withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_encrypted_value: Option<String>,
}

impl DisplayItem {
    /// A plain label+value item, i.e. every field without an `encryption`
    /// annotation.
    pub fn new(label: String, value: String) -> Self {
        Self {
            label,
            value,
            raw_encrypted_value: None,
        }
    }
}

/// Rendering context passed through the pipeline (immutable).
struct RenderContext<'a> {
    descriptor: &'a Descriptor,
    decoded: &'a DecodedArguments,
    chain_id: u64,
    data_provider: &'a dyn DataProvider,
    descriptors: &'a [ResolvedDescriptor],
    depth: u8,
    /// Decryptions already resolved for this frame's arguments — a field is read
    /// for visibility, for its entry and for `interpolatedIntent`, and the wallet
    /// must only be asked once. Nested calldata frames get their own, since the
    /// same handle under a different `@.to` is a different access check.
    decryption: DecryptionCache,
}

type RenderDiagnostics = Vec<FormatDiagnostic>;

/// Format calldata into a display model using a descriptor.
///
/// `descriptors` provides pre-resolved inner descriptors for nested calldata support.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn format_calldata(
    descriptor: &Descriptor,
    chain_id: u64,
    _to: &str,
    decoded: &DecodedArguments,
    _value: Option<&[u8]>,
    data_provider: &dyn DataProvider,
    descriptors: &[ResolvedDescriptor],
    state: &mut RenderState,
) -> Result<DisplayModel, Error> {
    // Find matching format by function name + signature
    let format = find_format(descriptor, &decoded.function_name, &decoded.selector)?;

    let ctx = RenderContext {
        descriptor,
        decoded,
        chain_id,
        data_provider,
        descriptors,
        depth: 0,
        decryption: DecryptionCache::default(),
    };

    let mut warnings = RenderDiagnostics::new();
    let mut nested_fallback = false;
    let expanded_fields = expand_display_fields(descriptor, &format.fields, &mut warnings);
    let entries =
        render_fields(&ctx, &expanded_fields, &mut warnings, &mut nested_fallback).await?;

    let interpolated = match format.interpolated_intent.as_ref() {
        Some(template) => {
            match interpolate_intent(template, &ctx, &expanded_fields, &format.excluded).await {
                Ok(rendered) => Some(rendered),
                Err(err) => {
                    warnings.push(render_warning(
                        RenderDiagnosticKind::InterpolatedIntentSkipped,
                        format!("interpolated intent skipped: {err}"),
                    ));
                    None
                }
            }
        }
        None => None,
    };

    let model = DisplayModel {
        intent: format
            .intent
            .as_ref()
            .map(crate::types::display::intent_as_string)
            .unwrap_or_else(|| decoded.function_name.clone()),
        interpolated_intent: interpolated,
        entries,
        owner: descriptor.metadata.owner.clone(),
        contract_name: descriptor.metadata.contract_name.clone(),
    };

    record_diagnostics(state, &warnings);
    if nested_fallback {
        state.mark_nested_fallback();
    }

    Ok(model)
}

/// Find the display format matching the decoded function.
///
/// Per spec: wallets MUST reject if multiple keys share the same type-only signature
/// (duplicate selectors).
fn find_format<'a>(
    descriptor: &'a Descriptor,
    function_name: &str,
    selector: &[u8; 4],
) -> Result<&'a DisplayFormat, Error> {
    let selector_hex = hex::encode(selector);
    let mut matches: Vec<(&str, &'a DisplayFormat)> = Vec::new();

    for (key, format) in &descriptor.display.formats {
        if key == function_name {
            matches.push((key, format));
            continue;
        }
        if key.contains('(') {
            if let Ok(parsed) = crate::decoder::parse_signature(key) {
                if hex::encode(parsed.selector) == selector_hex {
                    matches.push((key, format));
                }
            }
        }
    }

    match matches.len() {
        0 => Err(Error::Render(format!(
            "no display format found for function '{}' (selector 0x{})",
            function_name, selector_hex
        ))),
        1 => Ok(matches[0].1),
        _ => {
            let keys: Vec<&str> = matches.iter().map(|(k, _)| *k).collect();
            Err(Error::Descriptor(format!(
                "duplicate selectors (0x{}) found for keys: {}",
                selector_hex,
                keys.join(", ")
            )))
        }
    }
}

/// Render a list of display fields into display entries.
///
/// Uses `Pin<Box<dyn Future>>` to support recursive calls (references, groups).
/// Fold a field-level `encryption` block (sibling of `params` per the ERC-7730
/// spec) into the `FormatParams` handed to `format_value`, which reads
/// `params.encryption` to decide whether to emit the fallback label. Field-level
/// encryption wins only when params-level encryption is absent.
pub(crate) fn with_field_encryption(
    params: &Option<FormatParams>,
    encryption: &Option<EncryptionParams>,
) -> Option<FormatParams> {
    match encryption {
        None => params.clone(),
        Some(enc) => {
            let mut p = params.clone().unwrap_or_default();
            if p.encryption.is_none() {
                p.encryption = Some(enc.clone());
            }
            Some(p)
        }
    }
}

fn render_fields<'a>(
    ctx: &'a RenderContext<'a>,
    fields: &[DisplayField],
    warnings: &'a mut RenderDiagnostics,
    nested_fallback: &'a mut bool,
) -> Pin<Box<dyn Future<Output = Result<Vec<DisplayEntry>, Error>> + Send + 'a>> {
    let fields = fields.to_vec();
    Box::pin(async move {
        let mut entries = Vec::new();

        for field in &fields {
            match field {
                DisplayField::Group { field_group } => {
                    entries.extend(
                        render_field_group_entries(ctx, field_group, warnings, nested_fallback)
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
                    separator,
                    visible,
                } => {
                    // Fold field-level encryption into params so format_value can
                    // surface the fallback label for encrypted handles.
                    let params = with_field_encryption(params, encryption);
                    // If literal value is provided (no path), resolve constant refs and use it
                    if let Some(lit) = literal_value {
                        if !check_visibility(visible, &None, label, "")? {
                            continue;
                        }
                        let resolved = resolve_metadata_constant_str(ctx.descriptor, lit);
                        entries.push(DisplayEntry::Item(DisplayItem::new(
                            label.clone(),
                            resolved,
                        )));
                        continue;
                    }

                    let path_str = path.as_deref().unwrap_or("");

                    // Check for .[] array iteration — expand into one entry per element
                    if let Some((base, rest)) = split_array_iter_path(path_str) {
                        if let Some(ArgumentValue::Array(items)) = resolve_path(ctx.decoded, base) {
                            for (i, item) in items.iter().enumerate() {
                                let val = if rest.is_empty() {
                                    Some(item.clone())
                                } else {
                                    let rest_segments: Vec<&str> = rest.split('.').collect();
                                    navigate_value(item, &rest_segments)
                                };
                                let item_params = index_array_params(params.as_ref(), i);
                                if !is_field_visible(
                                    ctx,
                                    visible,
                                    &val,
                                    item_params.as_ref(),
                                    label,
                                    path_str,
                                    warnings,
                                )
                                .await?
                                {
                                    continue;
                                }
                                let formatted = format_value(
                                    ctx,
                                    &val,
                                    format.as_ref(),
                                    item_params.as_ref(),
                                    path_str,
                                    label,
                                    separator.as_deref(),
                                    warnings,
                                )
                                .await?;
                                entries.push(DisplayEntry::Item(DisplayItem {
                                    label: label.clone(),
                                    value: formatted,
                                    raw_encrypted_value: raw_encrypted_value(
                                        &val,
                                        item_params.as_ref(),
                                    ),
                                }));
                            }
                            continue;
                        }
                    }

                    // Resolve the value from decoded arguments
                    let value = resolve_path(ctx.decoded, path_str);

                    // Check visibility
                    if !is_field_visible(
                        ctx,
                        visible,
                        &value,
                        params.as_ref(),
                        label,
                        path_str,
                        warnings,
                    )
                    .await?
                    {
                        continue;
                    }

                    // Check excluded paths
                    if let Some(fmt) = find_current_format(ctx) {
                        if is_excluded_path(&fmt.excluded, path_str) {
                            continue;
                        }
                    }

                    // Intercept calldata format — produces a Nested entry instead of a flat value
                    if matches!(format.as_ref(), Some(FieldFormat::Calldata)) {
                        let entry = render_calldata_field(
                            ctx,
                            &value,
                            params.as_ref(),
                            label,
                            warnings,
                            nested_fallback,
                        )
                        .await?;
                        entries.push(entry);
                        continue;
                    }

                    let formatted = format_value(
                        ctx,
                        &value,
                        format.as_ref(),
                        params.as_ref(),
                        path_str,
                        label,
                        separator.as_deref(),
                        warnings,
                    )
                    .await?;

                    entries.push(DisplayEntry::Item(DisplayItem {
                        label: label.clone(),
                        value: formatted,
                        raw_encrypted_value: raw_encrypted_value(&value, params.as_ref()),
                    }));
                }
                DisplayField::Reference { .. } | DisplayField::Scope { .. } => {
                    warnings.push(render_warning(
                        RenderDiagnosticKind::GenericRenderWarning,
                        "unexpanded display field reached renderer; skipping",
                    ));
                }
            }
        }

        Ok(entries)
    })
}

enum GroupRenderKind {
    Scalar(Vec<DisplayItem>),
    Bundles(Vec<Vec<DisplayItem>>),
}

pub(crate) fn flatten_display_entry(entry: DisplayEntry) -> Vec<DisplayItem> {
    match entry {
        DisplayEntry::Item(item) => vec![item],
        DisplayEntry::Group { items, .. } => items,
        DisplayEntry::Nested { intent, .. } => {
            vec![DisplayItem::new("Nested call".to_string(), intent)]
        }
    }
}

fn render_group_field_kind<'a>(
    ctx: &'a RenderContext<'a>,
    field: &'a DisplayField,
    warnings: &'a mut RenderDiagnostics,
    nested_fallback: &'a mut bool,
) -> Pin<Box<dyn Future<Output = Result<GroupRenderKind, Error>> + Send + 'a>> {
    Box::pin(async move {
        match field {
            DisplayField::Group { field_group } => {
                render_group_kind(ctx, field_group, warnings, nested_fallback).await
            }
            DisplayField::Simple {
                path,
                label,
                value: literal_value,
                format,
                params,
                encryption,
                separator,
                visible,
            } => {
                let params = with_field_encryption(params, encryption);
                if let Some(lit) = literal_value {
                    if !check_visibility(visible, &None, label, "")? {
                        return Ok(GroupRenderKind::Scalar(Vec::new()));
                    }
                    return Ok(GroupRenderKind::Scalar(vec![DisplayItem::new(
                        label.clone(),
                        resolve_metadata_constant_str(ctx.descriptor, lit),
                    )]));
                }

                let path_str = path.as_deref().unwrap_or("");
                if let Some((base, rest)) = split_array_iter_path(path_str) {
                    if let Some(ArgumentValue::Array(items)) = resolve_path(ctx.decoded, base) {
                        let mut bundles = Vec::new();
                        for (i, item) in items.iter().enumerate() {
                            let val = if rest.is_empty() {
                                Some(item.clone())
                            } else {
                                let rest_segments: Vec<&str> = rest.split('.').collect();
                                navigate_value(item, &rest_segments)
                            };
                            let item_params = index_array_params(params.as_ref(), i);
                            if !is_field_visible(
                                ctx,
                                visible,
                                &val,
                                item_params.as_ref(),
                                label,
                                path_str,
                                warnings,
                            )
                            .await?
                            {
                                continue;
                            }
                            let rendered = if matches!(format.as_ref(), Some(FieldFormat::Calldata))
                            {
                                flatten_display_entry(
                                    render_calldata_field(
                                        ctx,
                                        &val,
                                        item_params.as_ref(),
                                        label,
                                        warnings,
                                        nested_fallback,
                                    )
                                    .await?,
                                )
                            } else {
                                vec![DisplayItem {
                                    label: label.clone(),
                                    value: format_value(
                                        ctx,
                                        &val,
                                        format.as_ref(),
                                        item_params.as_ref(),
                                        path_str,
                                        label,
                                        separator.as_deref(),
                                        warnings,
                                    )
                                    .await?,
                                    raw_encrypted_value: raw_encrypted_value(
                                        &val,
                                        item_params.as_ref(),
                                    ),
                                }]
                            };
                            bundles.push(rendered);
                        }
                        return Ok(GroupRenderKind::Bundles(bundles));
                    }
                }

                let value = resolve_path(ctx.decoded, path_str);
                if !is_field_visible(
                    ctx,
                    visible,
                    &value,
                    params.as_ref(),
                    label,
                    path_str,
                    warnings,
                )
                .await?
                {
                    return Ok(GroupRenderKind::Scalar(Vec::new()));
                }

                if matches!(format.as_ref(), Some(FieldFormat::Calldata)) {
                    return Ok(GroupRenderKind::Scalar(flatten_display_entry(
                        render_calldata_field(
                            ctx,
                            &value,
                            params.as_ref(),
                            label,
                            warnings,
                            nested_fallback,
                        )
                        .await?,
                    )));
                }

                Ok(GroupRenderKind::Scalar(vec![DisplayItem {
                    label: label.clone(),
                    value: format_value(
                        ctx,
                        &value,
                        format.as_ref(),
                        params.as_ref(),
                        path_str,
                        label,
                        separator.as_deref(),
                        warnings,
                    )
                    .await?,
                    raw_encrypted_value: raw_encrypted_value(&value, params.as_ref()),
                }]))
            }
            DisplayField::Reference { .. } | DisplayField::Scope { .. } => {
                Ok(GroupRenderKind::Scalar(Vec::new()))
            }
        }
    })
}

fn render_group_kind<'a>(
    ctx: &'a RenderContext<'a>,
    group: &'a FieldGroup,
    warnings: &'a mut RenderDiagnostics,
    nested_fallback: &'a mut bool,
) -> Pin<Box<dyn Future<Output = Result<GroupRenderKind, Error>> + Send + 'a>> {
    Box::pin(async move {
        let mut child_kinds = Vec::new();
        for field in &group.fields {
            child_kinds.push(render_group_field_kind(ctx, field, warnings, nested_fallback).await?);
        }

        match group.iteration {
            Iteration::Sequential => {
                let all_bundles = !child_kinds.is_empty()
                    && child_kinds
                        .iter()
                        .all(|k| matches!(k, GroupRenderKind::Bundles(_)));
                let items = if all_bundles {
                    // Element-major: keep each array element's fields contiguous
                    // (e.g. [amount0, addr0, amount1, addr1]) rather than grouping
                    // all of one field's elements together.
                    let mut sets: Vec<_> = child_kinds
                        .into_iter()
                        .map(|k| match k {
                            GroupRenderKind::Bundles(b) => b,
                            GroupRenderKind::Scalar(_) => Vec::new(),
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
                            GroupRenderKind::Scalar(items) => items,
                            GroupRenderKind::Bundles(bundles) => {
                                bundles.into_iter().flatten().collect()
                            }
                        })
                        .collect()
                };
                Ok(GroupRenderKind::Scalar(items))
            }
            Iteration::Bundled => {
                let mut bundle_sets = Vec::new();
                for kind in child_kinds {
                    match kind {
                        GroupRenderKind::Bundles(bundles) => bundle_sets.push(bundles),
                        GroupRenderKind::Scalar(_) => {
                            return Err(Error::Render(
                                "bundled groups cannot mix array-expanded and scalar fields"
                                    .to_string(),
                            ));
                        }
                    }
                }

                if bundle_sets.is_empty() {
                    return Ok(GroupRenderKind::Bundles(Vec::new()));
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
                Ok(GroupRenderKind::Bundles(bundled))
            }
        }
    })
}

/// Render a field group recursively.
async fn render_field_group_entries<'a>(
    ctx: &'a RenderContext<'a>,
    group: &FieldGroup,
    warnings: &'a mut RenderDiagnostics,
    nested_fallback: &'a mut bool,
) -> Result<Vec<DisplayEntry>, Error> {
    let rendered = render_group_kind(ctx, group, warnings, nested_fallback).await?;
    match rendered {
        GroupRenderKind::Scalar(items) => {
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
        GroupRenderKind::Bundles(bundles) => {
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

/// Resolve a `$ref` to a definition.
///
/// Accepts both ERC-7730 spec format (`$.display.definitions.foo`) and
/// legacy JSON Pointer format (`#/definitions/foo`).
fn resolve_reference(descriptor: &Descriptor, reference: &str) -> Option<DisplayField> {
    let key = reference
        .strip_prefix("$.display.definitions.")
        .or_else(|| reference.strip_prefix("#/definitions/"))?;
    descriptor.display.definitions.get(key).cloned()
}

/// Resolve references and scope prefixes into a concrete field tree before rendering.
pub(crate) fn expand_display_fields(
    descriptor: &Descriptor,
    fields: &[DisplayField],
    warnings: &mut RenderDiagnostics,
) -> Vec<DisplayField> {
    let mut expanded = Vec::new();

    for field in fields {
        match field {
            DisplayField::Reference {
                reference,
                path,
                params: ref_params,
                encryption: ref_encryption,
                visible,
            } => {
                if let Some(resolved) = resolve_reference(descriptor, reference) {
                    let merged = merge_ref_with_definition(
                        resolved,
                        path,
                        ref_params,
                        ref_encryption,
                        visible,
                    );
                    expanded.extend(expand_display_fields(descriptor, &[merged], warnings));
                } else {
                    warnings.push(render_warning(
                        RenderDiagnosticKind::DefinitionReferenceUnresolved,
                        format!("unresolved reference: {reference}"),
                    ));
                }
            }
            DisplayField::Group { field_group } => {
                let scoped_children = if let Some(scope_path) = field_group.path.as_deref() {
                    field_group
                        .fields
                        .iter()
                        .map(|field| prepend_scope_path(field, scope_path))
                        .collect()
                } else {
                    field_group.fields.clone()
                };
                expanded.push(DisplayField::Group {
                    field_group: FieldGroup {
                        path: None,
                        label: field_group.label.clone(),
                        iteration: field_group.iteration.clone(),
                        fields: expand_display_fields(descriptor, &scoped_children, warnings),
                    },
                });
            }
            DisplayField::Scope {
                path: scope_path,
                label,
                iteration,
                fields: children,
            } => {
                let scoped_children = if let Some(scope_path) = scope_path.as_deref() {
                    children
                        .iter()
                        .map(|child| prepend_scope_path(child, scope_path))
                        .collect()
                } else {
                    children.clone()
                };
                expanded.push(DisplayField::Group {
                    field_group: FieldGroup {
                        path: None,
                        label: label.clone(),
                        iteration: iteration.clone(),
                        fields: expand_display_fields(descriptor, &scoped_children, warnings),
                    },
                });
            }
            // Fold a field-level `encryption` block into `params` here, once, so
            // every consumer of the expanded fields sees it — the renderer, the
            // group renderer and `interpolatedIntent` alike. Missing it in any one
            // of them would leak the raw ciphertext into that output.
            DisplayField::Simple {
                path,
                label,
                value,
                format,
                params,
                encryption,
                separator,
                visible,
            } => expanded.push(DisplayField::Simple {
                path: path.clone(),
                label: label.clone(),
                value: value.clone(),
                format: format.clone(),
                params: with_field_encryption(params, encryption),
                encryption: encryption.clone(),
                separator: separator.clone(),
                visible: visible.clone(),
            }),
        }
    }

    expanded
}

/// Prepend a scope path to all path fields in a `DisplayField`.
///
/// Per ERC-7730 spec, inline scope groups concatenate parent paths with child paths.
/// Also prepends to `tokenPath` in params when the token path is relative (no `#.` prefix).
pub fn prepend_scope_path(field: &DisplayField, scope: &str) -> DisplayField {
    match field {
        DisplayField::Reference {
            reference,
            path,
            params,
            encryption,
            visible,
        } => DisplayField::Reference {
            reference: reference.clone(),
            path: Some(prepend_path(scope, path.as_deref())),
            params: params.as_ref().map(|p| prepend_params(scope, p)),
            encryption: encryption.clone(),
            visible: visible.clone(),
        },
        DisplayField::Group { field_group } => DisplayField::Group {
            field_group: FieldGroup {
                path: field_group
                    .path
                    .as_deref()
                    .map(|path| prepend_path(scope, Some(path))),
                label: field_group.label.clone(),
                iteration: field_group.iteration.clone(),
                fields: field_group.fields.clone(),
            },
        },
        DisplayField::Scope {
            path,
            label,
            iteration,
            fields: children,
        } => DisplayField::Scope {
            path: Some(prepend_path(scope, path.as_deref())),
            label: label.clone(),
            iteration: iteration.clone(),
            fields: children.clone(),
        },
        DisplayField::Simple {
            path,
            label,
            value,
            format,
            params,
            encryption,
            separator,
            visible,
        } => DisplayField::Simple {
            path: Some(prepend_path(scope, path.as_deref())),
            label: label.clone(),
            value: value.clone(),
            format: format.clone(),
            params: params.as_ref().map(|p| prepend_params(scope, p)),
            encryption: encryption.clone(),
            separator: separator.clone(),
            visible: visible.clone(),
        },
    }
}

/// Concatenate scope + child path. If child is empty/None, return scope.
fn prepend_path(scope: &str, child: Option<&str>) -> String {
    match child {
        Some(p) if !p.is_empty() => format!("{scope}.{p}"),
        _ => scope.to_string(),
    }
}

/// Prepend scope to relative paths in FormatParams (tokenPath, etc.).
fn prepend_params(scope: &str, params: &FormatParams) -> FormatParams {
    let mut p = params.clone();
    // Prepend scope to tokenPath if it's a relative name (no # prefix, no @. prefix)
    if let Some(ref tp) = p.token_path {
        if !tp.starts_with('#') && !tp.starts_with("@.") {
            p.token_path = Some(format!("{scope}.{tp}"));
        }
    }
    p
}

/// Merge a resolved definition with the reference's own path, params, and visible.
///
/// The definition provides label + format + base params. The reference provides
/// path, overriding params, and visible. Reference params win on conflict.
pub fn merge_ref_with_definition(
    definition: DisplayField,
    ref_path: &Option<String>,
    ref_params: &Option<FormatParams>,
    ref_encryption: &Option<EncryptionParams>,
    ref_visible: &VisibleRule,
) -> DisplayField {
    match definition {
        DisplayField::Simple {
            path: def_path,
            label,
            value,
            format,
            params: def_params,
            encryption: def_encryption,
            separator,
            visible: _,
        } => {
            // Reference encryption overrides the definition's; either lives at
            // field level (sibling of params) per the ERC-7730 spec.
            let encryption = ref_encryption.clone().or(def_encryption);
            // Reference path takes precedence over definition path
            let path = ref_path.clone().or(def_path);

            // Merge params: start with definition, overlay reference
            let params = match (def_params, ref_params) {
                (None, None) => None,
                (Some(dp), None) => Some(dp),
                (None, Some(rp)) => Some(rp.clone()),
                (Some(mut dp), Some(rp)) => {
                    // Reference params override definition params
                    if let Some(v) = &rp.token_path {
                        dp.token_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.native_currency_address {
                        dp.native_currency_address = Some(v.clone());
                    }
                    if let Some(v) = &rp.threshold {
                        dp.threshold = Some(v.clone());
                    }
                    if let Some(v) = &rp.message {
                        dp.message = Some(v.clone());
                    }
                    if let Some(v) = &rp.ref_path {
                        dp.ref_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.callee_path {
                        dp.callee_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.amount_path {
                        dp.amount_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.spender_path {
                        dp.spender_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.selector_path {
                        dp.selector_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.chain_id_path {
                        dp.chain_id_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.encoding {
                        dp.encoding = Some(v.clone());
                    }
                    if rp.prefix.is_some() {
                        dp.prefix = rp.prefix;
                    }
                    if let Some(v) = &rp.base {
                        dp.base = Some(v.clone());
                    }
                    if rp.decimals.is_some() {
                        dp.decimals = rp.decimals;
                    }
                    if let Some(v) = &rp.types {
                        dp.types = Some(v.clone());
                    }
                    if let Some(v) = &rp.sources {
                        dp.sources = Some(v.clone());
                    }
                    if let Some(v) = &rp.map_reference {
                        dp.map_reference = Some(v.clone());
                    }
                    if let Some(v) = &rp.enum_path {
                        dp.enum_path = Some(v.clone());
                    }
                    if rp.chain_id.is_some() {
                        dp.chain_id = rp.chain_id;
                    }
                    if let Some(v) = &rp.sender_address {
                        dp.sender_address = Some(v.clone());
                    }
                    if let Some(v) = &rp.collection_path {
                        dp.collection_path = Some(v.clone());
                    }
                    if let Some(v) = &rp.collection {
                        dp.collection = Some(v.clone());
                    }
                    if let Some(v) = &rp.encryption {
                        dp.encryption = Some(v.clone());
                    }
                    Some(dp)
                }
            };

            DisplayField::Simple {
                path,
                label,
                value,
                format,
                params,
                encryption,
                separator,
                visible: ref_visible.clone(),
            }
        }
        // If the definition is itself a reference or group, return as-is
        other => other,
    }
}

/// Resolve a path like `@.to` or `@.args[0]` to a decoded value.
///
/// When the path starts with `@.`, container values (appended last by
/// `inject_container_values`) take priority over function params with the
/// same name.  Without the prefix, function params are matched first.
pub(crate) fn resolve_path(decoded: &DecodedArguments, path: &str) -> Option<ArgumentValue> {
    let path = path.trim();

    // Strip `#.` prefix (v2 spec: root reference for structured data)
    let path = path.strip_prefix("#.").unwrap_or(path);

    // Detect `@.` prefix — means "prefer container value" for named lookup
    let (prefer_container, path) = if let Some(stripped) = path.strip_prefix("@.") {
        (true, stripped)
    } else {
        (false, path)
    };

    // Try numeric index first (positional: "0", "1", etc.)
    if let Ok(index) = path.parse::<usize>() {
        return decoded.args.get(index).map(|a| a.value.clone());
    }

    // Try named parameter matching by splitting dotted paths
    let segments: Vec<&str> = path.split('.').collect();

    // First segment indexes into top-level args
    if let Ok(index) = segments[0].parse::<usize>() {
        if let Some(arg) = decoded.args.get(index) {
            if segments.len() == 1 {
                return Some(arg.value.clone());
            }
            return navigate_value(&arg.value, &segments[1..]);
        }
    }

    // Handle array index notation: "args[0]"
    if let Some(rest) = segments[0].strip_prefix("args") {
        if let Some(idx_str) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Ok(index) = idx_str.parse::<usize>() {
                if let Some(arg) = decoded.args.get(index) {
                    if segments.len() == 1 {
                        return Some(arg.value.clone());
                    }
                    return navigate_value(&arg.value, &segments[1..]);
                }
            }
        }
    }

    // Try named parameter matching
    // When `@.` prefix was present, search from the end (container values are appended last)
    let name = segments[0];
    let arg = if prefer_container {
        decoded
            .args
            .iter()
            .rfind(|a| a.name.as_deref() == Some(name))
    } else {
        decoded
            .args
            .iter()
            .find(|a| a.name.as_deref() == Some(name))
    };

    if let Some(arg) = arg {
        if segments.len() == 1 {
            return Some(arg.value.clone());
        }
        return navigate_value(&arg.value, &segments[1..]);
    }

    None
}

/// Navigate into a value using path segments.
///
/// Supports `[index]` and `[start:end]` slice notation.
fn navigate_value(value: &ArgumentValue, segments: &[&str]) -> Option<ArgumentValue> {
    if segments.is_empty() {
        return Some(value.clone());
    }

    match value {
        ArgumentValue::Tuple(members) => {
            let seg = segments[0];

            // Numeric index
            if let Ok(index) = seg.parse::<usize>() {
                return members
                    .get(index)
                    .and_then(|(_, v)| navigate_value(v, &segments[1..]));
            }

            // Name fallback: match by member name
            members
                .iter()
                .find(|(name, _)| name.as_deref() == Some(seg))
                .and_then(|(_, v)| navigate_value(v, &segments[1..]))
        }
        ArgumentValue::Array(members) => {
            let seg = segments[0];
            match apply_collection_access(members, seg)? {
                CollectionSelection::Item(item) => navigate_value(&item, &segments[1..]),
                CollectionSelection::Slice(slice) => {
                    navigate_value(&ArgumentValue::Array(slice), &segments[1..])
                }
            }
        }
        ArgumentValue::Bytes(bytes)
        | ArgumentValue::FixedBytes(bytes)
        | ArgumentValue::Uint(bytes)
        | ArgumentValue::Int(bytes) => {
            let seg = segments[0];
            match apply_collection_access(bytes, seg)? {
                CollectionSelection::Item(byte) => {
                    navigate_value(&ArgumentValue::Bytes(vec![byte]), &segments[1..])
                }
                CollectionSelection::Slice(slice) => {
                    navigate_value(&ArgumentValue::Bytes(slice), &segments[1..])
                }
            }
        }
        _ => None,
    }
}

/// Split a path at `.[]` into (base_path, remaining_path).
///
/// `"_owners.[]"` → `Some(("_owners", ""))`
/// `"orders.[].order.expiry"` → `Some(("orders", "order.expiry"))`
/// `"_swapData.[].callData"` → `Some(("_swapData", "callData"))`
/// `"no_brackets"` → `None`
pub(crate) fn split_array_iter_path(path: &str) -> Option<(&str, &str)> {
    let marker = ".[]";
    let pos = path.find(marker)?;
    let base = &path[..pos];
    let rest = &path[pos + marker.len()..];
    // Strip leading dot from remaining path
    let rest = rest.strip_prefix('.').unwrap_or(rest);
    Some((base, rest))
}

/// Scope the element-relative `tokenPath` to the array element being rendered
/// by rewriting its first `.[]` to a concrete index, so `tokenPath`
/// `details.[].token` resolves to `details.[index].token` for element `index`.
/// No-op when `tokenPath` is absent or has no `.[]`. Only `tokenPath` is
/// rewritten; other element-relative path params (`calleePath`, `amountPath`,
/// `spenderPath`) are not scoped here. Shared by the calldata and EIP-712 flat
/// array-iteration paths (field rendering + interpolation).
pub(crate) fn index_array_params(
    params: Option<&FormatParams>,
    index: usize,
) -> Option<FormatParams> {
    let mut params = params.cloned()?;
    if let Some(token_path) = params.token_path.as_ref() {
        params.token_path = Some(token_path.replacen(".[]", &format!(".[{index}]"), 1));
    }
    Some(params)
}

fn visibility_context(label: &str, path: &str) -> String {
    if path.is_empty() {
        format!("field '{}'", label)
    } else {
        format!("field '{}' (path '{}')", label, path)
    }
}

/// Check if a field should be visible based on the visibility rule and decoded value.
fn check_visibility(
    rule: &VisibleRule,
    value: &Option<ArgumentValue>,
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
                        visibility_context(label, path)
                    )));
                }
                return Ok(true);
            };

            let json_val = val.to_json_value();
            if cond.hides_for_if_not_in(&json_val) {
                return Ok(false);
            }
            if cond.must_match.is_some() {
                if cond.matches_must_match(&json_val) {
                    return Ok(false);
                }
                return Err(Error::Render(format!(
                    "{} failed visible.mustMatch",
                    visibility_context(label, path)
                )));
            }
            Ok(true)
        }
    }
}

pub(crate) fn selector_from_argument_value(val: &ArgumentValue) -> Option<[u8; 4]> {
    match val {
        ArgumentValue::FixedBytes(bytes) | ArgumentValue::Bytes(bytes) if bytes.len() >= 4 => {
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&bytes[..4]);
            Some(selector)
        }
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) if bytes.len() >= 4 => {
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&bytes[bytes.len() - 4..]);
            Some(selector)
        }
        _ => None,
    }
}

pub(crate) fn chain_id_from_argument_value(val: &ArgumentValue) -> Option<u64> {
    match val {
        ArgumentValue::Uint(bytes) => {
            let n = BigUint::from_bytes_be(bytes);
            u64::try_from(n).ok()
        }
        _ => None,
    }
}

pub(crate) fn uint_bytes_from_argument_value(val: &ArgumentValue) -> Option<Vec<u8>> {
    match val {
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

pub(crate) fn uint_bytes_from_biguint(value: &BigUint, param_name: &str) -> Result<Vec<u8>, Error> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(Error::Descriptor(format!(
            "nested calldata param '{}' exceeds 32 bytes",
            param_name
        )));
    }
    let mut padded = vec![0u8; 32usize.saturating_sub(bytes.len())];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

pub(crate) fn parse_nested_amount_literal(
    value: &UintLiteral,
    param_name: &str,
) -> Result<Vec<u8>, Error> {
    let biguint = value.to_biguint().ok_or_else(|| {
        Error::Descriptor(format!(
            "invalid nested calldata param '{}': expected a non-negative integer",
            param_name
        ))
    })?;
    uint_bytes_from_biguint(&biguint, param_name)
}

pub(crate) fn parse_nested_selector_param(value: &str, param_name: &str) -> Result<[u8; 4], Error> {
    let hex_str = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes = hex::decode(hex_str).map_err(|_| {
        Error::Descriptor(format!(
            "invalid nested calldata param '{}': expected 4-byte hex selector",
            param_name
        ))
    })?;
    if bytes.len() != 4 {
        return Err(Error::Descriptor(format!(
            "invalid nested calldata param '{}': expected 4-byte hex selector",
            param_name
        )));
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&bytes);
    Ok(selector)
}

pub(crate) fn parse_nested_address_param(value: &str, param_name: &str) -> Result<String, Error> {
    let hex_str = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes = hex::decode(hex_str).map_err(|_| {
        Error::Descriptor(format!(
            "invalid nested calldata param '{}': expected 20-byte hex address",
            param_name
        ))
    })?;
    let addr = address_bytes_from_raw_bytes(&bytes).ok_or_else(|| {
        Error::Descriptor(format!(
            "invalid nested calldata param '{}': expected 20-byte hex address",
            param_name
        ))
    })?;
    Ok(format!("0x{}", hex::encode(addr)))
}

pub(crate) fn normalized_nested_calldata(
    inner_calldata: &[u8],
    selector_override: Option<[u8; 4]>,
) -> Vec<u8> {
    match selector_override {
        Some(selector) if !inner_calldata.starts_with(&selector) => {
            let mut normalized = selector.to_vec();
            normalized.extend_from_slice(inner_calldata);
            normalized
        }
        _ => inner_calldata.to_vec(),
    }
}

pub(crate) fn ensure_single_nested_param_source(
    constant_present: bool,
    path_present: bool,
    param_name: &str,
) -> Result<(), Error> {
    if constant_present && path_present {
        return Err(Error::Descriptor(format!(
            "nested calldata param '{}' cannot specify both constant and path forms",
            param_name
        )));
    }
    Ok(())
}

fn resolve_nested_callee(
    decoded: &DecodedArguments,
    params: Option<&FormatParams>,
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
    Ok(params
        .callee_path
        .as_ref()
        .and_then(|path| resolve_path(decoded, path))
        .and_then(|value| address_string_from_argument_value(&value)))
}

fn resolve_nested_spender(
    decoded: &DecodedArguments,
    params: Option<&FormatParams>,
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
    Ok(params
        .spender_path
        .as_ref()
        .and_then(|path| resolve_path(decoded, path))
        .and_then(|value| address_string_from_argument_value(&value)))
}

fn resolve_nested_amount(
    decoded: &DecodedArguments,
    params: Option<&FormatParams>,
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
    Ok(params
        .amount_path
        .as_ref()
        .and_then(|path| resolve_path(decoded, path))
        .and_then(|value| uint_bytes_from_argument_value(&value)))
}

fn resolve_nested_chain_id(
    decoded: &DecodedArguments,
    params: Option<&FormatParams>,
    default_chain_id: u64,
) -> Result<u64, Error> {
    let Some(params) = params else {
        return Ok(default_chain_id);
    };
    ensure_single_nested_param_source(
        params.chain_id.is_some(),
        params.chain_id_path.is_some(),
        "chainId",
    )?;
    if let Some(chain_id) = params.chain_id {
        return Ok(chain_id);
    }
    Ok(params
        .chain_id_path
        .as_ref()
        .and_then(|path| resolve_path(decoded, path))
        .and_then(|value| chain_id_from_argument_value(&value))
        .unwrap_or(default_chain_id))
}

fn resolve_nested_selector(
    decoded: &DecodedArguments,
    params: Option<&FormatParams>,
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
    Ok(params
        .selector_path
        .as_ref()
        .and_then(|path| resolve_path(decoded, path))
        .and_then(|value| selector_from_argument_value(&value)))
}

/// Raw big-endian bytes backing an `ArgumentValue` (the ciphertext/handle to
/// hand to the wallet for decryption).
fn argument_value_bytes(v: &ArgumentValue) -> Vec<u8> {
    match v {
        ArgumentValue::Address(a) => a.to_vec(),
        ArgumentValue::Uint(b)
        | ArgumentValue::Int(b)
        | ArgumentValue::Bytes(b)
        | ArgumentValue::FixedBytes(b) => b.clone(),
        ArgumentValue::Bool(x) => vec![u8::from(*x)],
        ArgumentValue::String(s) => s.as_bytes().to_vec(),
        ArgumentValue::Array(_) | ArgumentValue::Tuple(_) => Vec::new(),
    }
}

/// The value an encrypted field carries in the signing request, 0x-hex, for
/// [`DisplayItem::raw_encrypted_value`]. `None` for a field with no `encryption`
/// annotation, or one whose path did not resolve.
fn raw_encrypted_value(
    value: &Option<ArgumentValue>,
    params: Option<&FormatParams>,
) -> Option<String> {
    params.and_then(|p| p.encryption.as_ref())?;
    let bytes = argument_value_bytes(value.as_ref()?);
    Some(format!("0x{}", hex::encode(bytes)))
}

/// Build a typed `ArgumentValue` from a decrypted plaintext, driven by the
/// descriptor's declared category (never by the bytes' shape). Integer
/// plaintexts arrive as 32-byte two's-complement words, so they render exactly
/// like an ABI-decoded argument of the same value.
fn argument_value_from_plaintext(kind: PlainKind, bytes: Vec<u8>) -> ArgumentValue {
    match kind {
        PlainKind::Uint => ArgumentValue::Uint(bytes),
        PlainKind::Int => ArgumentValue::Int(bytes),
        PlainKind::Bool => ArgumentValue::Bool(bytes.iter().any(|&b| b != 0)),
        PlainKind::String => ArgumentValue::String(String::from_utf8_lossy(&bytes).into_owned()),
        PlainKind::Bytes => ArgumentValue::Bytes(bytes),
        PlainKind::Address => {
            // Right-align the (at most 20) bytes into a 20-byte address.
            let mut a = [0u8; 20];
            let n = bytes.len().min(20);
            a[20 - n..].copy_from_slice(&bytes[bytes.len() - n..]);
            ArgumentValue::Address(a)
        }
    }
}

/// What an encrypted field renders from: the plaintext, or the text standing in
/// for it.
enum FieldPlaintext {
    Value(ArgumentValue),
    /// The field's `fallbackLabel` (or a generic placeholder) — never the
    /// ciphertext.
    Fallback(String),
}

/// Decrypt a field value via the wallet and re-interpret the plaintext as the
/// descriptor's declared `plaintextType`.
///
/// Memoized on the render frame, so the wallet is asked once per encrypted value
/// however many times the field is read. `Err` is a malformed annotation, which
/// is fatal like any other descriptor error.
async fn decrypt_field_value(
    ctx: &RenderContext<'_>,
    encrypted: &ArgumentValue,
    enc: &EncryptionParams,
    warnings: &mut RenderDiagnostics,
) -> Result<FieldPlaintext, Error> {
    // The contract the ciphertext is accessed through (container's `@.to`).
    let contract_address = resolve_path(ctx.decoded, "@.to")
        .filter(|v| matches!(v, ArgumentValue::Address(_)))
        .map(|v| format_address(&v));

    let outcome = ctx
        .decryption
        .resolve(
            ctx.data_provider,
            Some(ctx.chain_id),
            contract_address.as_deref(),
            &argument_value_bytes(encrypted),
            enc,
            warnings,
        )
        .await?;

    Ok(match outcome {
        Decryption::Plaintext { kind, bytes } => {
            FieldPlaintext::Value(argument_value_from_plaintext(kind, bytes))
        }
        Decryption::Fallback { text, .. } => FieldPlaintext::Fallback(text),
    })
}

/// Whether a field is visible, evaluating conditional rules against the value
/// the user is actually signing.
///
/// Plain fields evaluate their own decoded value. An encrypted field evaluates
/// its decrypted plaintext: `visible.mustMatch` / `ifNotIn` describe the
/// cleartext, and comparing them against the ciphertext handle is meaningless —
/// `mustMatch` would reject values that do match, and `ifNotIn` would decide
/// visibility on a comparison nobody verified.
///
/// When decryption is unavailable the plaintext is unknown, so the rule sees
/// `None`: an unverifiable condition never hides the field, and `mustMatch`
/// still refuses to pass it silently. (The TypeScript library evaluates the rule
/// against the handle in that case, which reaches the same outcome for both rule
/// kinds — a handle is never in an `ifNotIn` list, and never satisfies
/// `mustMatch` — but says something the ciphertext cannot support.)
///
/// Rules that ignore the value never trigger decryption at all — no wallet
/// prompt for a field whose visibility does not depend on it. TypeScript
/// decrypts before evaluating any rule and drops the warning with the hidden
/// field, so this asks the wallet strictly less often for the same output.
async fn is_field_visible(
    ctx: &RenderContext<'_>,
    rule: &VisibleRule,
    value: &Option<ArgumentValue>,
    params: Option<&FormatParams>,
    label: &str,
    path: &str,
    warnings: &mut RenderDiagnostics,
) -> Result<bool, Error> {
    let Some(enc) = params.and_then(|p| p.encryption.as_ref()) else {
        return check_visibility(rule, value, label, path);
    };
    // A descriptor bug is rejected wherever it appears, even on a field this rule
    // is about to hide — no wallet round-trip needed to notice it.
    validate_annotation(enc)?;

    let plaintext = match (rule, value) {
        (VisibleRule::Condition(_), Some(val)) => {
            match decrypt_field_value(ctx, val, enc, warnings).await? {
                FieldPlaintext::Value(plaintext) => Some(plaintext),
                FieldPlaintext::Fallback(_) => None,
            }
        }
        _ => return check_visibility(rule, value, label, path),
    };
    check_visibility(rule, &plaintext, label, path)
}

/// Format a decoded value according to its format type.
#[allow(clippy::too_many_arguments)]
async fn format_value(
    ctx: &RenderContext<'_>,
    value: &Option<ArgumentValue>,
    format: Option<&FieldFormat>,
    params: Option<&FormatParams>,
    path: &str,
    label: &str,
    separator: Option<&str>,
    warnings: &mut RenderDiagnostics,
) -> Result<String, Error> {
    let Some(val) = value else {
        warnings.push(render_warning(
            RenderDiagnosticKind::ValueUnresolved,
            format!("could not resolve path: {} for field '{}'", path, label),
        ));
        return Ok("<unresolved>".to_string());
    };

    // Encryption (ERC-7730 `encryption`): decrypt via the wallet, then render the
    // plaintext with the field's regular format (e.g. tokenAmount → "1 cUSDC").
    // When decryption is unavailable the field renders its `fallbackLabel`; a
    // malformed annotation degrades the same way, distinguished by diagnostic.
    let decrypted_owned;
    if let Some(enc) = params.and_then(|p| p.encryption.as_ref()) {
        match decrypt_field_value(ctx, val, enc, warnings).await? {
            FieldPlaintext::Value(plaintext) => decrypted_owned = Some(plaintext),
            FieldPlaintext::Fallback(text) => return Ok(text),
        }
    } else {
        decrypted_owned = None;
    }
    // From here on `val` is the decrypted plaintext when decryption succeeded.
    let val: &ArgumentValue = decrypted_owned.as_ref().unwrap_or(val);

    // Check for map reference
    if let Some(params) = params {
        if let Some(ref map_ref) = params.map_reference {
            if let Some(mapped) = resolve_map(ctx, map_ref, val) {
                return Ok(mapped);
            }
        }
    }

    let Some(fmt) = format else {
        return Ok(format_raw_with_separator(val, separator));
    };

    match fmt {
        FieldFormat::TokenAmount => {
            format_token_amount(ctx, val, params, label, path, warnings).await
        }
        FieldFormat::Amount => format_amount(ctx, val),
        FieldFormat::Date => {
            format_date(ctx, val, params.and_then(|p| p.encoding.as_deref())).await
        }
        FieldFormat::Enum => format_enum(ctx, val, params),
        FieldFormat::Address => Ok(format_address(val)),
        FieldFormat::AddressName => format_address_name(ctx, val, params).await,
        FieldFormat::Number => Ok(format_number(val)),
        FieldFormat::Raw => Ok(format_raw_with_separator(val, separator)),
        FieldFormat::TokenTicker => format_token_ticker(ctx, val, params, warnings).await,
        FieldFormat::ChainId => format_chain_id(val),
        FieldFormat::Duration => Ok(format_duration(val)?),
        FieldFormat::Unit => Ok(format_unit(ctx.descriptor, val, params)?),
        FieldFormat::Calldata => {
            // Should not reach here — calldata format is intercepted in render_fields
            warnings.push(render_warning(
                RenderDiagnosticKind::GenericRenderWarning,
                format!(
                    "calldata format should be handled by render_calldata_field for field '{}' (path: {})",
                    label, path
                ),
            ));
            Ok(format_raw(val))
        }
        FieldFormat::NftName => format_nft_name(ctx, val, params, label, path, warnings).await,
        FieldFormat::InteroperableAddressName => {
            // ERC-7930 is nascent — delegate to addressName with a warning
            warnings.push(render_warning(
                RenderDiagnosticKind::InteroperableAddressNameFallback,
                "interoperableAddressName: falling back to addressName",
            ));
            format_address_name(ctx, val, params).await
        }
    }
}

/// Render a nested calldata field by decoding the inner call and recursively formatting it.
async fn render_calldata_field(
    ctx: &RenderContext<'_>,
    val: &Option<ArgumentValue>,
    params: Option<&FormatParams>,
    label: &str,
    warnings: &mut RenderDiagnostics,
    nested_fallback: &mut bool,
) -> Result<DisplayEntry, Error> {
    // Extract bytes from value
    let inner_calldata = match val {
        Some(ArgumentValue::Bytes(bytes)) => bytes,
        _ => {
            let raw = val
                .as_ref()
                .map(format_raw)
                .unwrap_or_else(|| "<unresolved>".to_string());
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedCalldataInvalidType,
                "calldata field is not bytes",
            ));
            *nested_fallback = true;
            return Ok(DisplayEntry::Item(DisplayItem::new(label.to_string(), raw)));
        }
    };

    // Check depth limit
    if ctx.depth >= MAX_CALLDATA_DEPTH {
        warnings.push(render_warning(
            RenderDiagnosticKind::NestedCalldataDegraded,
            format!(
                "nested calldata depth limit ({}) reached",
                MAX_CALLDATA_DEPTH
            ),
        ));
        *nested_fallback = true;
        return Ok(raw_calldata_scalar(label, inner_calldata));
    }

    let callee = match resolve_nested_callee(ctx.decoded, params)? {
        Some(addr) => addr,
        None => {
            // No callee — return raw preview
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedCalldataDegraded,
                "nested calldata callee could not be resolved",
            ));
            *nested_fallback = true;
            return Ok(raw_calldata_scalar(label, inner_calldata));
        }
    };

    let amount_bytes = resolve_nested_amount(ctx.decoded, params)?;
    let spender_addr = resolve_nested_spender(ctx.decoded, params)?;
    let inner_chain_id = resolve_nested_chain_id(ctx.decoded, params, ctx.chain_id)?;
    let selector_override = resolve_nested_selector(ctx.decoded, params)?;
    let normalized_calldata = normalized_nested_calldata(inner_calldata, selector_override);

    if normalized_calldata.len() < 4 {
        warnings.push(render_warning(
            RenderDiagnosticKind::NestedCalldataDegraded,
            "inner calldata too short",
        ));
        *nested_fallback = true;
        return Ok(raw_calldata_scalar(label, inner_calldata));
    }

    // Find matching inner descriptor by chain_id + callee address
    let inner_descriptor = ctx.descriptors.iter().find(|rd| {
        rd.descriptor.context.deployments().iter().any(|dep| {
            dep.chain_id == inner_chain_id && dep.address.to_lowercase() == callee.to_lowercase()
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
            return Ok(raw_calldata_scalar(label, inner_calldata));
        }
    };

    let mut actual_selector = [0u8; 4];
    actual_selector.copy_from_slice(&normalized_calldata[..4]);

    // Find matching signature
    let (sig, _format_key) =
        match crate::find_matching_signature(inner_descriptor, &actual_selector) {
            Ok(result) => result,
            Err(_) => {
                warnings.push(render_warning(
                    RenderDiagnosticKind::NestedDescriptorNotFound,
                    "No matching descriptor for inner call",
                ));
                *nested_fallback = true;
                return Ok(raw_calldata_scalar(label, inner_calldata));
            }
        };

    // Decode inner calldata
    let mut decoded = match crate::decoder::decode_calldata(&sig, &normalized_calldata) {
        Ok(d) => d,
        Err(_) => {
            warnings.push(render_warning(
                RenderDiagnosticKind::NestedCalldataDegraded,
                "inner calldata could not be decoded",
            ));
            *nested_fallback = true;
            return Ok(raw_calldata_scalar(label, inner_calldata));
        }
    };

    // Inject container values into inner context
    crate::inject_container_values(
        &mut decoded,
        inner_chain_id,
        &callee,
        amount_bytes.as_deref(),
        spender_addr.as_deref(),
    );

    // Build inner render context
    let inner_format =
        match find_format(inner_descriptor, &decoded.function_name, &decoded.selector) {
            Ok(f) => f,
            Err(_) => {
                warnings.push(render_warning(
                    RenderDiagnosticKind::NestedDescriptorNotFound,
                    "No matching descriptor for inner call",
                ));
                *nested_fallback = true;
                return Ok(raw_calldata_scalar(label, inner_calldata));
            }
        };

    let inner_ctx = RenderContext {
        descriptor: inner_descriptor,
        decoded: &decoded,
        chain_id: inner_chain_id,
        data_provider: ctx.data_provider,
        descriptors: ctx.descriptors,
        depth: ctx.depth + 1,
        decryption: DecryptionCache::default(),
    };

    let mut inner_warnings = Vec::new();
    let inner_expanded =
        expand_display_fields(inner_descriptor, &inner_format.fields, &mut inner_warnings);
    let inner_entries = render_fields(
        &inner_ctx,
        &inner_expanded,
        &mut inner_warnings,
        nested_fallback,
    )
    .await?;

    warnings.extend(inner_warnings);

    let intent = inner_format
        .intent
        .as_ref()
        .map(crate::types::display::intent_as_string)
        .unwrap_or_else(|| decoded.function_name.clone());

    Ok(DisplayEntry::Nested {
        label: label.to_string(),
        intent,
        owner: inner_descriptor.metadata.owner.clone(),
        entries: inner_entries,
    })
}

/// Render inner calldata that could not be clear-signed as a scalar hex value.
/// A `calldata` field always has a scalar representation; a nested sub-call is
/// attached only when the inner call resolves and decodes.
pub(crate) fn raw_calldata_scalar(label: &str, calldata: &[u8]) -> DisplayEntry {
    DisplayEntry::Item(DisplayItem::new(
        label.to_string(),
        format!("0x{}", hex::encode(calldata)),
    ))
}

/// Find the current display format from context (for excluded paths, etc.).
fn find_current_format<'a>(ctx: &RenderContext<'a>) -> Option<&'a DisplayFormat> {
    let selector_hex = hex::encode(ctx.decoded.selector);
    for (key, format) in &ctx.descriptor.display.formats {
        if key == &ctx.decoded.function_name {
            return Some(format);
        }
        if key.contains('(') {
            if let Ok(parsed) = crate::decoder::parse_signature(key) {
                if hex::encode(parsed.selector) == selector_hex {
                    return Some(format);
                }
            }
        }
    }
    None
}

/// Format a raw value with an optional separator for arrays.
fn format_raw_with_separator(val: &ArgumentValue, separator: Option<&str>) -> String {
    match val {
        ArgumentValue::Array(items) => {
            let sep = separator.unwrap_or(", ");
            let rendered: Vec<String> = items.iter().map(format_raw).collect();
            if separator.is_some() {
                // With explicit separator, no brackets
                rendered.join(sep)
            } else {
                format!("[{}]", rendered.join(sep))
            }
        }
        _ => format_raw(val),
    }
}

fn format_raw(val: &ArgumentValue) -> String {
    match val {
        ArgumentValue::Address(addr) => eip55_checksum(addr),
        ArgumentValue::Uint(bytes) => BigUint::from_bytes_be(bytes).to_string(),
        // ERC-7730 defines `raw` as "the natural representation of the
        // underlying structured data type", and for `intN` that is signed.
        // Sharing the unsigned arm printed a tick of -140 as 2^256 - 140 —
        // not a wrong-looking number, but a plausible-looking huge one, on a
        // screen whose whole purpose is telling someone what they are signing.
        ArgumentValue::Int(bytes) => int_to_bigint(bytes).to_string(),
        ArgumentValue::Bool(b) => b.to_string(),
        ArgumentValue::Bytes(b) | ArgumentValue::FixedBytes(b) => {
            format!("0x{}", hex::encode(b))
        }
        ArgumentValue::String(s) => s.clone(),
        ArgumentValue::Array(items) => {
            let rendered: Vec<String> = items.iter().map(format_raw).collect();
            format!("[{}]", rendered.join(", "))
        }
        ArgumentValue::Tuple(items) => {
            let rendered: Vec<String> = items.iter().map(|(_, v)| format_raw(v)).collect();
            format!("({})", rendered.join(", "))
        }
    }
}

pub(crate) fn address_bytes_from_raw_bytes(bytes: &[u8]) -> Option<[u8; 20]> {
    let addr_bytes = match bytes.len() {
        20 => bytes,
        32 => &bytes[12..32],
        _ => return None,
    };
    let mut addr = [0u8; 20];
    addr.copy_from_slice(addr_bytes);
    Some(addr)
}

pub(crate) fn address_bytes_from_argument_value(val: &ArgumentValue) -> Option<[u8; 20]> {
    match val {
        ArgumentValue::Address(addr) => Some(*addr),
        ArgumentValue::Uint(bytes)
        | ArgumentValue::Int(bytes)
        | ArgumentValue::Bytes(bytes)
        | ArgumentValue::FixedBytes(bytes) => address_bytes_from_raw_bytes(bytes),
        _ => None,
    }
}

pub(crate) fn address_string_from_argument_value(val: &ArgumentValue) -> Option<String> {
    address_bytes_from_argument_value(val).map(|addr| format!("0x{}", hex::encode(addr)))
}

fn format_address(val: &ArgumentValue) -> String {
    address_bytes_from_argument_value(val)
        .map(|addr| eip55_checksum(&addr))
        .unwrap_or_else(|| format_raw(val))
}

/// Format an address as a trusted name (spec: addressName).
///
/// 1. Check senderAddress match → "Sender"
/// 2. Try local name via provider
/// 3. Try ENS name via provider
/// 4. Fallback → EIP-55 checksum
async fn format_address_name(
    ctx: &RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
) -> Result<String, Error> {
    let Some(addr) = address_bytes_from_argument_value(val) else {
        return Ok(format_raw(val));
    };

    let hex_addr = format!("0x{}", hex::encode(addr));

    // 1. Check senderAddress
    if let Some(params) = params {
        if let Some(ref sender) = params.sender_address {
            let sender_addrs = match sender {
                SenderAddress::Single(s) => vec![s.as_str()],
                SenderAddress::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
            };
            for sender_ref in &sender_addrs {
                // Resolve path references like "@.from"
                let resolved_addr = if sender_ref.starts_with("@.") || sender_ref.starts_with('#') {
                    resolve_path(ctx.decoded, sender_ref)
                        .and_then(|v| address_string_from_argument_value(&v))
                } else {
                    Some(resolve_metadata_constant_str(ctx.descriptor, sender_ref))
                };
                if let Some(resolved) = resolved_addr {
                    if resolved.to_lowercase() == hex_addr.to_lowercase() {
                        return Ok("Sender".to_string());
                    }
                }
            }
        }
    }

    // 2. Determine allowed sources (default: both)
    let sources = params.and_then(|p| p.sources.as_ref());
    let local_allowed = sources
        .map(|s| s.iter().any(|src| src == "local"))
        .unwrap_or(true);
    let ens_allowed = sources
        .map(|s| s.iter().any(|src| src == "ens"))
        .unwrap_or(true);

    // 3. Try local name
    if local_allowed {
        if let Some(name) = ctx
            .data_provider
            .resolve_local_name(
                &hex_addr,
                ctx.chain_id,
                params.and_then(|p| p.types.as_deref()),
            )
            .await
        {
            return Ok(name);
        }
    }

    // 4. Try ENS name
    if ens_allowed {
        if let Some(name) = ctx
            .data_provider
            .resolve_ens_name(
                &hex_addr,
                ctx.chain_id,
                params.and_then(|p| p.types.as_deref()),
            )
            .await
        {
            return Ok(name);
        }
    }

    // 5. Fallback: EIP-55 checksum
    Ok(eip55_checksum(&addr))
}

/// EIP-55 mixed-case checksum encoding.
pub(crate) fn eip55_checksum(addr: &[u8; 20]) -> String {
    use tiny_keccak::{Hasher, Keccak};

    let hex_addr = hex::encode(addr);
    let mut hasher = Keccak::v256();
    hasher.update(hex_addr.as_bytes());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        let hash_nibble = if i.is_multiple_of(2) {
            (hash[i / 2] >> 4) & 0x0f
        } else {
            hash[i / 2] & 0x0f
        };
        if hash_nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }
    result
}

fn format_number(val: &ArgumentValue) -> String {
    match val {
        ArgumentValue::Int(bytes) => int_to_bigint(bytes).to_string(),
        _ => coerce_unsigned_decimal_string_from_argument_value(val)
            .unwrap_or_else(|| format_raw(val)),
    }
}

fn unsigned_biguint_from_argument_value_including_int(val: &ArgumentValue) -> Option<BigUint> {
    match val {
        ArgumentValue::Int(bytes) => Some(BigUint::from_bytes_be(bytes)),
        _ => None,
    }
    .or_else(|| coerce_unsigned_biguint_from_argument_value(val))
}

fn unsigned_decimal_string_from_argument_value_including_int(
    val: &ArgumentValue,
) -> Option<String> {
    unsigned_biguint_from_argument_value_including_int(val).map(|n| n.to_string())
}

fn unsigned_biguint_from_argument_value_for_amount(val: &ArgumentValue) -> Option<BigUint> {
    match val {
        ArgumentValue::Int(bytes) => Some(BigUint::from_bytes_be(bytes)),
        _ => coerce_unsigned_biguint_from_argument_value(val),
    }
}

/// Convert signed integer bytes (two's complement, big-endian) to BigInt.
pub(crate) fn int_to_bigint(bytes: &[u8]) -> BigInt {
    if bytes.is_empty() {
        return BigInt::from(0);
    }
    // Check sign bit (MSB of first byte)
    if bytes[0] & 0x80 != 0 {
        // Negative: compute -(~value + 1) = -(complement + 1)
        let inverted: Vec<u8> = bytes.iter().map(|b| !b).collect();
        let magnitude = BigUint::from_bytes_be(&inverted) + 1u64;
        BigInt::from_biguint(Sign::Minus, magnitude)
    } else {
        BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_be(bytes))
    }
}

async fn format_token_amount(
    ctx: &RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
    label: &str,
    path: &str,
    warnings: &mut RenderDiagnostics,
) -> Result<String, Error> {
    let Some(raw_amount) = unsigned_biguint_from_argument_value_including_int(val) else {
        return Ok(format_raw(val));
    };

    // Determine chain ID for token lookup (cross-chain support)
    let lookup_chain_id = resolve_chain_id(ctx, params);

    // Try to resolve token metadata
    let token_meta = if let Some(params) = params {
        if let Some(ref token_path) = params.token_path {
            // Resolve token address from calldata (supports address and uint256-packed addresses)
            let token_addr = resolve_path(ctx.decoded, token_path);
            let addr_hex = token_addr
                .as_ref()
                .and_then(address_string_from_argument_value);
            if let Some(ref addr_hex) = addr_hex {
                // Check for native currency
                if let Some(ref native) = params.native_currency_address {
                    if native.matches(addr_hex, &ctx.descriptor.metadata.constants) {
                        Some(native_token_meta(lookup_chain_id))
                    } else {
                        ctx.data_provider
                            .resolve_token(lookup_chain_id, addr_hex)
                            .await
                    }
                } else {
                    ctx.data_provider
                        .resolve_token(lookup_chain_id, addr_hex)
                        .await
                }
            } else {
                None
            }
        } else if let Some(ref token_ref) = params.token {
            // Static token address or $.metadata.constants.* ref
            let addr = resolve_metadata_constant_str(ctx.descriptor, token_ref);
            if let Some(ref native) = params.native_currency_address {
                if native.matches(&addr, &ctx.descriptor.metadata.constants) {
                    Some(native_token_meta(lookup_chain_id))
                } else {
                    ctx.data_provider
                        .resolve_token(lookup_chain_id, &addr)
                        .await
                }
            } else {
                ctx.data_provider
                    .resolve_token(lookup_chain_id, &addr)
                    .await
            }
        } else {
            None
        }
    } else {
        None
    };

    if token_meta.is_none() {
        warnings.push(render_warning(
            RenderDiagnosticKind::TokenMetadataNotFound,
            format!(
                "token metadata not found for field '{}' (path: {})",
                label, path
            ),
        ));
    }

    Ok(format_token_amount_output(
        ctx.descriptor,
        &raw_amount,
        params,
        token_meta.as_ref(),
    ))
}

async fn format_token_ticker(
    ctx: &RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
    warnings: &mut RenderDiagnostics,
) -> Result<String, Error> {
    let lookup_chain_id = resolve_chain_id(ctx, params);

    if let Some(addr_hex) = address_string_from_argument_value(val) {
        if let Some(meta) = ctx
            .data_provider
            .resolve_token(lookup_chain_id, &addr_hex)
            .await
        {
            return Ok(meta.symbol);
        }
    }

    warnings.push(render_warning(
        RenderDiagnosticKind::TokenTickerNotFound,
        "token ticker not found",
    ));
    Ok(format_raw(val))
}

fn format_chain_id(val: &ArgumentValue) -> Result<String, Error> {
    if let ArgumentValue::Uint(bytes) = val {
        let n = BigUint::from_bytes_be(bytes);
        let chain_id: u64 = n.try_into().unwrap_or(0);
        Ok(chain_name(chain_id))
    } else {
        Ok(format_raw(val))
    }
}

/// Resolve the chain ID for cross-chain token lookups.
fn resolve_chain_id(ctx: &RenderContext<'_>, params: Option<&FormatParams>) -> u64 {
    if let Some(params) = params {
        // Static chain ID takes precedence
        if let Some(cid) = params.chain_id {
            return cid;
        }
        // Dynamic chain ID from calldata path
        if let Some(ref path) = params.chain_id_path {
            if let Some(ArgumentValue::Uint(bytes)) = resolve_path(ctx.decoded, path) {
                let n = BigUint::from_bytes_be(&bytes);
                if let Ok(cid) = u64::try_from(n) {
                    return cid;
                }
            }
        }
    }
    ctx.chain_id
}

fn format_amount(ctx: &RenderContext<'_>, val: &ArgumentValue) -> Result<String, Error> {
    let Some(n) = unsigned_biguint_from_argument_value_for_amount(val) else {
        return Ok(format_raw(val));
    };

    // Per ERC-7730 the `amount` format is a native-currency amount.
    let meta = native_token_meta(ctx.chain_id);
    let formatted = format_with_decimals(&n, meta.decimals);
    Ok(format!("{} {}", formatted, meta.symbol))
}

async fn format_date(
    ctx: &RenderContext<'_>,
    val: &ArgumentValue,
    encoding: Option<&str>,
) -> Result<String, Error> {
    match val {
        ArgumentValue::Uint(bytes) => {
            let n = BigUint::from_bytes_be(bytes);
            if encoding == Some("blockheight") {
                let block_number = u64::try_from(&n).map_err(|_| {
                    Error::Render(format!("blockheight {} does not fit into u64", n))
                })?;
                return format_blockheight_timestamp(ctx.data_provider, ctx.chain_id, block_number)
                    .await;
            }

            let timestamp = i64::try_from(&n)
                .map_err(|_| Error::Render(format!("timestamp {} does not fit into i64", n)))?;
            format_timestamp(timestamp)
        }
        _ => Ok(format_raw(val)),
    }
}

fn format_enum(
    ctx: &RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
) -> Result<String, Error> {
    let raw = unsigned_decimal_string_from_argument_value_including_int(val)
        .unwrap_or_else(|| format_raw(val));

    if let Some(params) = params {
        // Try direct enumPath first
        if let Some(ref enum_path) = params.enum_path {
            if let Some(enum_def) = ctx.descriptor.metadata.enums.get(enum_path) {
                if let Some(label) = enum_def.get(&raw) {
                    return Ok(label.clone());
                }
            }
        }
        // Try $ref path (v2): "$.metadata.enums.interestRateMode"
        if let Some(ref ref_path) = params.ref_path {
            if let Some(enum_name) = ref_path.strip_prefix("$.metadata.enums.") {
                if let Some(enum_def) = ctx.descriptor.metadata.enums.get(enum_name) {
                    if let Some(label) = enum_def.get(&raw) {
                        return Ok(label.clone());
                    }
                }
            }
        }
    }

    Ok(raw)
}

/// Resolve a map reference to a display value.
///
/// If the map has `keyPath`, resolve the key from that path instead of the field's own value.
fn resolve_map(ctx: &RenderContext<'_>, map_ref: &str, val: &ArgumentValue) -> Option<String> {
    let key = if let Some(ref key_path) = ctx.descriptor.metadata.maps.get(map_ref)?.key_path {
        resolve_path(ctx.decoded, key_path).map(|v| format_raw(&v))?
    } else {
        format_raw(val)
    };
    lookup_map_entry(ctx.descriptor, map_ref, &key)
}

/// Format an NFT name: "{collection_name} #{token_id}" or "#{token_id}" fallback.
async fn format_nft_name(
    ctx: &RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
    label: &str,
    path: &str,
    warnings: &mut RenderDiagnostics,
) -> Result<String, Error> {
    // Extract token_id from uint value
    let token_id = match val {
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => {
            BigUint::from_bytes_be(bytes).to_string()
        }
        _ => return Ok(format_raw(val)),
    };

    // Resolve collection address
    let collection_addr = params.and_then(|p| {
        // Try collectionPath first
        if let Some(ref cpath) = p.collection_path {
            let resolved = resolve_path(ctx.decoded, cpath);
            if let Some(ArgumentValue::Address(addr)) = resolved {
                return Some(format!("0x{}", hex::encode(addr)));
            }
        }
        // Fallback to constant collection address
        p.collection.clone()
    });

    let Some(collection_addr) = collection_addr else {
        warnings.push(render_warning(
            RenderDiagnosticKind::NftCollectionAddressMissing,
            format!(
                "no collection address for nftName field '{}' (path: {})",
                label, path
            ),
        ));
        return Ok(token_id);
    };

    // Ask the provider for the collection name
    if let Some(name) = ctx
        .data_provider
        .resolve_nft_collection_name(&collection_addr, ctx.chain_id)
        .await
    {
        Ok(format!("{} #{}", name, token_id))
    } else {
        warnings.push(render_warning(
            RenderDiagnosticKind::NftCollectionNameNotFound,
            format!(
                "NFT collection not found for '{}' (address: {})",
                label, collection_addr
            ),
        ));
        Ok(format!("#{}", token_id))
    }
}

/// Interpolate `${path}` and `{name}` templates in an intent string.
///
/// Supports both v1 `${path}` and v2 `{paramName}` interpolation patterns.
/// Double braces `{{` and `}}` produce literal `{` and `}`.
async fn interpolate_intent(
    template: &str,
    ctx: &RenderContext<'_>,
    fields: &[DisplayField],
    excluded: &[String],
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
        let path = result[start + 2..end].to_string();
        let replacement =
            resolve_and_format_for_interpolation(ctx, fields, excluded, &path).await?;
        result.replace_range(start..=end, &replacement);
    }

    // Second pass: replace {name} patterns (v2) — only single `{` not preceded by `$`
    let mut pos = 0;
    while pos < result.len() {
        if let Some(rel_start) = result[pos..].find('{') {
            let start = pos + rel_start;
            // Skip if preceded by '$' (already handled)
            if start > 0 && result.as_bytes()[start - 1] == b'$' {
                pos = start + 1;
                continue;
            }
            let end = match result[start..].find('}') {
                Some(e) => start + e,
                None => break,
            };
            let path = result[start + 1..end].to_string();
            let replacement =
                resolve_and_format_for_interpolation(ctx, fields, excluded, &path).await?;
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

/// Format a duration value (seconds → `HH:MM:ss`).
fn format_duration(val: &ArgumentValue) -> Result<String, Error> {
    let secs = match val {
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => {
            let n = BigUint::from_bytes_be(bytes);
            u64::try_from(&n)
                .map_err(|_| Error::Render(format!("duration {} does not fit into u64", n)))?
        }
        _ => return Ok(format_raw(val)),
    };

    Ok(format_duration_seconds(secs))
}

/// Format a unit value (e.g., percentage, bps) with optional decimals and SI prefix.
fn format_unit(
    descriptor: &Descriptor,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
) -> Result<String, Error> {
    let Some(raw_val) = unsigned_biguint_from_argument_value_including_int(val) else {
        return Ok(format_raw(val));
    };

    let base = params
        .and_then(|p| p.base.as_deref())
        .map(|b| resolve_metadata_constant_str(descriptor, b))
        .unwrap_or_default();
    Ok(format_unit_biguint(&raw_val, &base, params))
}

async fn resolve_and_format_for_interpolation(
    ctx: &RenderContext<'_>,
    fields: &[DisplayField],
    excluded: &[String],
    path: &str,
) -> Result<String, Error> {
    let field = resolve_interpolation_field_spec(fields, excluded, path)?;

    // Array-iteration paths (`.[]`) format each element like field rendering and
    // join with " and "; a scalar `resolve_path` returns None for `.[]`, which
    // would otherwise drop the whole interpolatedIntent.
    if let Some((base, rest)) = split_array_iter_path(field.path) {
        if let Some(ArgumentValue::Array(items)) = resolve_path(ctx.decoded, base) {
            if !items.is_empty() {
                let mut parts = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    let val = if rest.is_empty() {
                        Some(item.clone())
                    } else {
                        navigate_value(item, &rest.split('.').collect::<Vec<_>>())
                    };
                    let item_params = index_array_params(field.params, i);
                    let mut warnings = RenderDiagnostics::new();
                    parts.push(
                        format_value(
                            ctx,
                            &val,
                            field.format,
                            item_params.as_ref(),
                            field.path,
                            field.label,
                            field.separator,
                            &mut warnings,
                        )
                        .await?,
                    );
                }
                return Ok(parts.join(" and "));
            }
        }
    }

    let value = resolve_path(ctx.decoded, field.path).ok_or_else(|| {
        Error::Descriptor(format!(
            "interpolatedIntent path '{}' could not be resolved from calldata",
            path
        ))
    })?;

    let mut warnings = RenderDiagnostics::new();
    format_value(
        ctx,
        &Some(value),
        field.format,
        field.params,
        field.path,
        field.label,
        field.separator,
        &mut warnings,
    )
    .await
}

pub(crate) fn record_diagnostics(state: &mut RenderState, diagnostics: &[FormatDiagnostic]) {
    for diagnostic in diagnostics {
        state.push_diagnostic(diagnostic.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::{DecodedArgument, ParamType};
    use crate::path::{parse_collection_access, CollectionAccess};

    #[test]
    fn raw_renders_signed_integers_as_signed() {
        // ERC-7730 calls `raw` "the natural representation of the underlying
        // structured data type". For `intN` that is signed, and a descriptor
        // author has no other way to ask for one: there is no signed-integer
        // format in the v2 schema, so `raw` is it.
        //
        // Sharing an arm with `Uint` printed the two's-complement word through
        // `BigUint`, so a Uniswap-style tick of -140 read as 2^256 - 140. That
        // is the failure mode worth a test: not a number that looks wrong, but
        // a plausible-looking enormous one, on the screen that exists to tell
        // someone what they are about to sign.
        let minus_140 = {
            let mut word = [0xffu8; 32];
            word[31] = 0x74; // -140 in two's complement
            word.to_vec()
        };
        assert_eq!(format_raw(&ArgumentValue::Int(minus_140)), "-140");

        // Same bytes as an unsigned word are unchanged: the fix must not move
        // the boundary, only stop crossing it.
        let mut max = [0xffu8; 32];
        max[31] = 0x74;
        assert_eq!(
            format_raw(&ArgumentValue::Uint(max.to_vec())),
            (num_bigint::BigUint::from_bytes_be(&max)).to_string()
        );

        // Positive signed values, zero, and the sign-bit boundary.
        assert_eq!(format_raw(&ArgumentValue::Int(vec![0x00; 32])), "0");
        let mut positive = [0u8; 32];
        positive[31] = 0x7f;
        assert_eq!(format_raw(&ArgumentValue::Int(positive.to_vec())), "127");
        let mut negative_one = [0xffu8; 32];
        negative_one[31] = 0xff;
        assert_eq!(format_raw(&ArgumentValue::Int(negative_one.to_vec())), "-1");
    }

    #[test]
    fn test_eip55_checksum() {
        // Known checksum: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        let addr_bytes = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);
        let checksummed = eip55_checksum(&addr);
        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_byte_slice_path_resolution_supports_bytes_fixedbytes_and_uint() {
        let decoded = DecodedArguments {
            function_name: "demo".to_string(),
            selector: [0; 4],
            args: vec![
                DecodedArgument {
                    index: 0,
                    name: Some("payload".to_string()),
                    param_type: ParamType::Bytes,
                    value: ArgumentValue::Bytes(vec![0x11, 0x22, 0x33, 0x44]),
                },
                DecodedArgument {
                    index: 1,
                    name: Some("packed".to_string()),
                    param_type: ParamType::FixedBytes(32),
                    value: ArgumentValue::FixedBytes(
                        hex::decode(
                            "000000000000000000000000b21d281dedb17ae5b501f6aa8256fe38c4e45757",
                        )
                        .unwrap(),
                    ),
                },
                DecodedArgument {
                    index: 2,
                    name: Some("packed_addr".to_string()),
                    param_type: ParamType::Uint(256),
                    value: ArgumentValue::Uint(
                        hex::decode(
                            "0000000000000000000000001111111111111111111111111111111111111111",
                        )
                        .unwrap(),
                    ),
                },
            ],
        };

        match resolve_path(&decoded, "payload.[1:3]") {
            Some(ArgumentValue::Bytes(bytes)) => assert_eq!(hex::encode(bytes), "2233"),
            other => panic!("unexpected payload slice: {other:?}"),
        }
        match resolve_path(&decoded, "packed.[-20:]") {
            Some(ArgumentValue::Bytes(bytes)) => {
                assert_eq!(
                    hex::encode(bytes),
                    "b21d281dedb17ae5b501f6aa8256fe38c4e45757"
                )
            }
            other => panic!("unexpected packed slice: {other:?}"),
        }
        match resolve_path(&decoded, "packed_addr.[-20:]") {
            Some(ArgumentValue::Bytes(bytes)) => {
                assert_eq!(
                    hex::encode(bytes),
                    "1111111111111111111111111111111111111111"
                )
            }
            other => panic!("unexpected packed uint slice: {other:?}"),
        }
    }

    #[test]
    fn test_enum_and_address_coercions_accept_byte_like_values() {
        let descriptor: Descriptor = serde_json::from_str(
            r#"{"context":{"contract":{"deployments":[]}},"metadata":{"owner":"test","enums":{"dex":{"82":"Single swap"}},"constants":{},"maps":{}},"display":{"definitions":{},"formats":{}}}"#,
        )
        .unwrap();
        let decoded = DecodedArguments {
            function_name: "demo".to_string(),
            selector: [0; 4],
            args: vec![],
        };
        let provider = crate::provider::EmptyDataProvider;
        let ctx = RenderContext {
            descriptor: &descriptor,
            decoded: &decoded,
            chain_id: 1,
            data_provider: &provider,
            descriptors: &[],
            depth: 0,
            decryption: DecryptionCache::default(),
        };
        let params: FormatParams =
            serde_json::from_value(serde_json::json!({"$ref": "$.metadata.enums.dex"})).unwrap();

        assert_eq!(
            format_enum(&ctx, &ArgumentValue::Bytes(vec![0x52]), Some(&params)).unwrap(),
            "Single swap"
        );
        assert_eq!(
            format_address(&ArgumentValue::Bytes(
                hex::decode("b21d281dedb17ae5b501f6aa8256fe38c4e45757").unwrap()
            )),
            "0xb21D281DEdb17AE5B501F6AA8256fe38C4e45757"
        );
    }

    #[test]
    fn test_shared_slice_parser_supports_open_ended_bounds() {
        assert_eq!(
            parse_collection_access("[:1]", 4),
            Some(CollectionAccess::Slice { start: 0, end: 1 })
        );
        assert_eq!(
            parse_collection_access("[-2:]", 4),
            Some(CollectionAccess::Slice { start: 2, end: 4 })
        );
        assert_eq!(parse_collection_access("[5:2]", 4), None);
    }

    #[tokio::test]
    async fn test_interpolate_intent() {
        use crate::provider::EmptyDataProvider;

        let decoded = DecodedArguments {
            function_name: "transfer".to_string(),
            selector: [0; 4],
            args: vec![
                DecodedArgument {
                    index: 0,
                    name: None,
                    param_type: ParamType::Address,
                    value: ArgumentValue::Address([0u8; 20]),
                },
                DecodedArgument {
                    index: 1,
                    name: None,
                    param_type: ParamType::Uint(256),
                    value: ArgumentValue::Uint(vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0x03, 0xe8,
                    ]),
                },
            ],
        };

        let descriptor: Descriptor = serde_json::from_str(
            r#"{"context":{"contract":{"deployments":[]}},"metadata":{"owner":"test","enums":{},"constants":{},"maps":{}},"display":{"definitions":{},"formats":{}}}"#
        ).unwrap();
        let data_provider = EmptyDataProvider;
        let ctx = RenderContext {
            descriptor: &descriptor,
            decoded: &decoded,
            chain_id: 1,
            data_provider: &data_provider,
            descriptors: &[],
            depth: 0,
            decryption: DecryptionCache::default(),
        };

        let fields = vec![
            DisplayField::Simple {
                path: Some("0".to_string()),
                label: "To".to_string(),
                value: None,
                format: Some(FieldFormat::Address),
                params: None,
                encryption: None,
                separator: None,
                visible: VisibleRule::Named(VisibleLiteral::Never),
            },
            DisplayField::Simple {
                path: Some("1".to_string()),
                label: "Amount".to_string(),
                value: None,
                format: Some(FieldFormat::Number),
                params: None,
                encryption: None,
                separator: None,
                visible: VisibleRule::Named(VisibleLiteral::Never),
            },
        ];

        let result = interpolate_intent("Send ${1} to ${0}", &ctx, &fields, &[])
            .await
            .unwrap();
        assert_eq!(
            result,
            "Send 1000 to 0x0000000000000000000000000000000000000000"
        );
    }

    #[tokio::test]
    async fn test_interpolate_intent_address_name() {
        use crate::types::display::{DisplayField, FieldFormat};

        // Provider that resolves a specific address to a local name
        struct MockLocalNameProvider;
        impl DataProvider for MockLocalNameProvider {
            fn resolve_local_name(
                &self,
                address: &str,
                _chain_id: u64,
                _types: Option<&[String]>,
            ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
                let addr = address.to_string();
                Box::pin(async move {
                    if addr.to_lowercase() == "0xbf01daf454dce008d3e2bfd47d5e186f71477253" {
                        Some("My Savings".to_string())
                    } else {
                        None
                    }
                })
            }
        }

        let mut addr_bytes = [0u8; 20];
        addr_bytes
            .copy_from_slice(&hex::decode("bf01daf454dce008d3e2bfd47d5e186f71477253").unwrap());

        let decoded = DecodedArguments {
            function_name: "withdraw".to_string(),
            selector: [0; 4],
            args: vec![DecodedArgument {
                index: 0,
                name: Some("to".to_string()),
                param_type: ParamType::Address,
                value: ArgumentValue::Address(addr_bytes),
            }],
        };

        let fields = vec![DisplayField::Simple {
            path: Some("to".to_string()),
            label: "Recipient".to_string(),
            value: None,
            format: Some(FieldFormat::AddressName),
            params: None,
            encryption: None,
            separator: None,
            visible: VisibleRule::Always,
        }];

        let descriptor: Descriptor = serde_json::from_str(
            r#"{"context":{"contract":{"deployments":[]}},"metadata":{"owner":"test","enums":{},"constants":{},"maps":{}},"display":{"definitions":{},"formats":{}}}"#,
        )
        .unwrap();
        let data_provider = MockLocalNameProvider;
        let ctx = RenderContext {
            descriptor: &descriptor,
            decoded: &decoded,
            chain_id: 1,
            data_provider: &data_provider,
            descriptors: &[],
            depth: 0,
            decryption: DecryptionCache::default(),
        };

        let result = interpolate_intent("Withdraw to {to}", &ctx, &fields, &[])
            .await
            .unwrap();
        assert_eq!(result, "Withdraw to My Savings");
    }
}
