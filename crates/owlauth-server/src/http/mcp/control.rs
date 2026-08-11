use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool, ToolAnnotations};
use serde_json::{Map, Value, json};
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const CONTROL_PATH_PREFIX: &str = "/v1/";
const IDEMPOTENCY_ARGUMENT: &str = "idempotency_key";
const REQUEST_BODY_ARGUMENT: &str = "body";

const HAND_DESIGNED_OPERATION_IDS: [&str; 9] = [
    "get_system",
    "list_projects",
    "get_project",
    "list_applications",
    "get_application",
    "list_webhook_endpoints",
    "list_webhook_deliveries",
    "list_project_users",
    "lookup_project_user_by_email",
];

#[derive(Clone, Debug)]
pub(super) struct ControlToolCatalog {
    operations: Arc<HashMap<String, ControlOperation>>,
    tools: Arc<Vec<Tool>>,
}

#[derive(Clone, Debug)]
struct ControlOperation {
    tool: Tool,
    method: Method,
    path_template: String,
    path_parameters: Vec<OperationParameter>,
    query_parameters: Vec<OperationParameter>,
    idempotency_key: Option<ArgumentRequirement>,
    body: Option<ArgumentRequirement>,
    accepted_arguments: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArgumentRequirement {
    Optional,
    Required,
}

impl ArgumentRequirement {
    const fn from_required(required: bool) -> Self {
        if required {
            Self::Required
        } else {
            Self::Optional
        }
    }

    const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

#[derive(Clone, Debug)]
struct OperationParameter {
    name: String,
    required: bool,
}

impl ControlToolCatalog {
    pub(super) fn from_control_openapi() -> Result<Self, String> {
        let document = serde_json::to_value(owlauth_types::control::openapi())
            .map_err(|error| format!("serialize Control OpenAPI: {error}"))?;
        let components = document
            .pointer("/components/schemas")
            .and_then(Value::as_object)
            .ok_or_else(|| "Control OpenAPI has no component schemas".to_owned())?;
        let paths = document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| "Control OpenAPI has no paths".to_owned())?;

        let mut operations = HashMap::new();
        for (path, path_item) in paths {
            if !path.starts_with(CONTROL_PATH_PREFIX) {
                continue;
            }
            let path_item = path_item
                .as_object()
                .ok_or_else(|| format!("Control OpenAPI path item {path} is not an object"))?;
            for method_name in ["get", "post", "put", "patch", "delete"] {
                let Some(operation) = path_item.get(method_name) else {
                    continue;
                };
                let operation_id = operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        format!("Control OpenAPI {method_name} {path} has no operationId")
                    })?;
                if HAND_DESIGNED_OPERATION_IDS.contains(&operation_id) {
                    continue;
                }
                let control_operation = ControlOperation::from_openapi(
                    method_name,
                    path,
                    operation_id,
                    operation,
                    components,
                )?;
                let tool_name = control_operation.tool.name.to_string();
                if operations
                    .insert(tool_name.clone(), control_operation)
                    .is_some()
                {
                    return Err(format!("duplicate generated MCP tool {tool_name}"));
                }
            }
        }

        let mut tools = operations
            .values()
            .map(|operation| operation.tool.clone())
            .collect::<Vec<_>>();
        tools.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Self {
            operations: Arc::new(operations),
            tools: Arc::new(tools),
        })
    }

    pub(super) fn tools(&self) -> Vec<Tool> {
        self.tools.as_ref().clone()
    }

    pub(super) fn get_tool(&self, name: &str) -> Option<Tool> {
        self.operations
            .get(name)
            .map(|operation| operation.tool.clone())
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.operations.contains_key(name)
    }

    pub(super) async fn call(
        &self,
        control_api: Router,
        name: &str,
        arguments: Option<JsonObject>,
        max_result_bytes: usize,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let operation = self.operations.get(name).ok_or_else(|| {
            rmcp::ErrorData::invalid_params(format!("unknown Control tool {name}"), None)
        })?;
        operation
            .call(control_api, arguments.unwrap_or_default(), max_result_bytes)
            .await
    }
}

impl ControlOperation {
    #[allow(
        clippy::too_many_lines,
        reason = "one conversion keeps each reviewed OpenAPI operation's parameters, body, schemas, and annotations visibly aligned"
    )]
    fn from_openapi(
        method_name: &str,
        path: &str,
        operation_id: &str,
        operation: &Value,
        components: &Map<String, Value>,
    ) -> Result<Self, String> {
        let method = Method::from_bytes(method_name.to_ascii_uppercase().as_bytes())
            .map_err(|error| format!("invalid OpenAPI method {method_name}: {error}"))?;
        let mut properties = Map::new();
        let mut required = Vec::new();
        let mut path_parameters = Vec::new();
        let mut query_parameters = Vec::new();
        let mut accepts_idempotency_key = false;
        let mut requires_idempotency_key = false;
        let mut accepted_arguments = BTreeSet::new();

        for parameter in operation
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = parameter
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{operation_id} has an unnamed parameter"))?;
            let location = parameter
                .get("in")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{operation_id} parameter {name} has no location"))?;
            let is_required = parameter
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let argument_name = match location {
                "path" | "query" => name,
                "header" if name.eq_ignore_ascii_case("idempotency-key") => {
                    accepts_idempotency_key = true;
                    requires_idempotency_key = is_required;
                    IDEMPOTENCY_ARGUMENT
                }
                _ => {
                    return Err(format!(
                        "{operation_id} has unsupported {location} parameter {name}"
                    ));
                }
            };
            if !accepted_arguments.insert(argument_name.to_owned()) {
                return Err(format!(
                    "{operation_id} maps more than one parameter to {argument_name}"
                ));
            }
            let mut schema = parameter
                .get("schema")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if let Some(description) = parameter.get("description").and_then(Value::as_str)
                && let Some(object) = schema.as_object_mut()
            {
                object
                    .entry("description")
                    .or_insert_with(|| Value::String(description.to_owned()));
            }
            properties.insert(
                argument_name.to_owned(),
                resolve_schema(&schema, components, &mut Vec::new())?,
            );
            if is_required {
                required.push(Value::String(argument_name.to_owned()));
            }
            let mapped = OperationParameter {
                name: argument_name.to_owned(),
                required: is_required,
            };
            match location {
                "path" => path_parameters.push(mapped),
                "query" => query_parameters.push(mapped),
                "header" => {}
                _ => unreachable!("unsupported parameter locations returned above"),
            }
        }

        let request_body = operation.get("requestBody");
        let accepts_body = request_body.is_some();
        let requires_body = request_body
            .and_then(|body| body.get("required"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if let Some(request_body) = request_body {
            let schema = request_body
                .pointer("/content/application~1json/schema")
                .ok_or_else(|| format!("{operation_id} has no JSON request-body schema"))?;
            accepted_arguments.insert(REQUEST_BODY_ARGUMENT.to_owned());
            properties.insert(
                REQUEST_BODY_ARGUMENT.to_owned(),
                resolve_schema(schema, components, &mut Vec::new())?,
            );
            if requires_body {
                required.push(Value::String(REQUEST_BODY_ARGUMENT.to_owned()));
            }
        }

        let input_schema = object_schema(properties, required);
        let idempotency_key = accepts_idempotency_key
            .then(|| ArgumentRequirement::from_required(requires_idempotency_key));
        let body = accepts_body.then(|| ArgumentRequirement::from_required(requires_body));
        let output_schema = success_output_schema(operation, components)?;
        let success_description = success_response(operation)
            .and_then(|response| response.get("description"))
            .and_then(Value::as_str)
            .unwrap_or("Execute the reviewed Control operation");
        let tool_name = format!("owlauth_{operation_id}");
        let title = operation_title(operation_id);
        let read_only = is_read_only_operation(&method, operation_id);
        let idempotent = read_only
            || matches!(method, Method::PUT | Method::PATCH | Method::DELETE)
            || accepts_idempotency_key;
        let destructive = !read_only && is_destructive_operation(operation_id);
        let open_world = is_open_world_operation(operation_id);
        let tool = Tool::new(
            tool_name,
            format!("{success_description}. Control {method} {path}."),
            schema_object(&input_schema, operation_id, "input")?,
        )
        .with_title(title.clone())
        .with_raw_output_schema(Arc::new(schema_object(
            &output_schema,
            operation_id,
            "output",
        )?))
        .with_annotations(ToolAnnotations::from_raw(
            Some(title),
            Some(read_only),
            Some(destructive),
            Some(idempotent),
            Some(open_world),
        ));

        Ok(Self {
            tool,
            method,
            path_template: path.to_owned(),
            path_parameters,
            query_parameters,
            idempotency_key,
            body,
            accepted_arguments,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one dispatch path keeps argument validation, fixed-route construction, in-process Control execution, and bounded response mapping together"
    )]
    async fn call(
        &self,
        control_api: Router,
        arguments: JsonObject,
        max_result_bytes: usize,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if arguments
            .keys()
            .any(|name| !self.accepted_arguments.contains(name.as_str()))
        {
            return Ok(invalid_arguments("unknown argument"));
        }

        let mut url = Url::parse("http://owlauth.internal/")
            .expect("the fixed internal Control dispatch URL is valid");
        {
            let mut segments = url
                .path_segments_mut()
                .expect("the fixed internal Control dispatch URL is hierarchical");
            segments.clear();
            for segment in self.path_template.trim_start_matches('/').split('/') {
                if let Some(parameter_name) = segment
                    .strip_prefix('{')
                    .and_then(|segment| segment.strip_suffix('}'))
                {
                    let Some(value) = arguments.get(parameter_name) else {
                        return Ok(invalid_arguments(&format!(
                            "missing required path argument {parameter_name}"
                        )));
                    };
                    let Some(value) = scalar_string(value) else {
                        return Ok(invalid_arguments(&format!(
                            "path argument {parameter_name} must be a string or integer"
                        )));
                    };
                    if matches!(value.as_ref(), "." | "..") {
                        return Ok(invalid_arguments(&format!(
                            "path argument {parameter_name} must not be a dot segment"
                        )));
                    }
                    segments.push(&value);
                } else {
                    segments.push(segment);
                }
            }
        }
        {
            let mut query = url.query_pairs_mut();
            for parameter in &self.query_parameters {
                match arguments.get(&parameter.name) {
                    Some(value) if !value.is_null() => {
                        let Some(value) = scalar_string(value) else {
                            return Ok(invalid_arguments(&format!(
                                "query argument {} must be a scalar value",
                                parameter.name
                            )));
                        };
                        query.append_pair(&parameter.name, &value);
                    }
                    _ if parameter.required => {
                        return Ok(invalid_arguments(&format!(
                            "missing required query argument {}",
                            parameter.name
                        )));
                    }
                    _ => {}
                }
            }
        }

        for parameter in &self.path_parameters {
            if parameter.required && !arguments.contains_key(&parameter.name) {
                return Ok(invalid_arguments(&format!(
                    "missing required path argument {}",
                    parameter.name
                )));
            }
        }
        let idempotency_key = arguments.get(IDEMPOTENCY_ARGUMENT).and_then(Value::as_str);
        if self
            .idempotency_key
            .is_some_and(ArgumentRequirement::is_required)
            && idempotency_key.is_none()
        {
            return Ok(invalid_arguments(&format!(
                "missing required {IDEMPOTENCY_ARGUMENT}"
            )));
        }
        if arguments.contains_key(IDEMPOTENCY_ARGUMENT) && idempotency_key.is_none() {
            return Ok(invalid_arguments(&format!(
                "{IDEMPOTENCY_ARGUMENT} must be a string"
            )));
        }
        if self.idempotency_key.is_none() && idempotency_key.is_some() {
            return Ok(invalid_arguments(&format!(
                "{IDEMPOTENCY_ARGUMENT} is not accepted by this operation"
            )));
        }

        let body = match arguments.get(REQUEST_BODY_ARGUMENT) {
            Some(value) if self.body.is_some() => serde_json::to_vec(value).map_err(|_| {
                rmcp::ErrorData::internal_error("serialize Control request body", None)
            })?,
            Some(_) => {
                return Ok(invalid_arguments("body is not accepted by this operation"));
            }
            None if self.body.is_some_and(ArgumentRequirement::is_required) => {
                return Ok(invalid_arguments("missing required body"));
            }
            None => Vec::new(),
        };

        let uri = format!(
            "{}{}",
            url.path(),
            url.query()
                .map_or_else(String::new, |query| format!("?{query}"))
        );
        let mut request = Request::builder()
            .method(self.method.clone())
            .uri(uri)
            .header(header::ACCEPT, "application/json")
            .body(Body::from(body))
            .map_err(|_| rmcp::ErrorData::internal_error("build Control request", None))?;
        request.extensions_mut().insert(Uuid::new_v4().to_string());
        if self.body.is_some() {
            request.headers_mut().insert(
                header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
        }
        if let Some(value) = idempotency_key {
            let Ok(value) = axum::http::HeaderValue::from_str(value) else {
                return Ok(invalid_arguments("invalid idempotency_key"));
            };
            request.headers_mut().insert("idempotency-key", value);
        }

        let response = control_api.oneshot(request).await.map_err(|error| {
            rmcp::ErrorData::internal_error(format!("Control dispatch failed: {error}"), None)
        })?;
        let status = response.status();
        let Ok(bytes) = to_bytes(response.into_body(), max_result_bytes).await else {
            return Ok(tool_error(
                "result_too_large",
                "The Control response exceeds the configured MCP result limit.",
            ));
        };
        let value = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&bytes).map_err(|_| {
                rmcp::ErrorData::internal_error("Control returned a non-JSON response", None)
            })?
        };
        if status.is_success() {
            Ok(CallToolResult::structured(value))
        } else {
            Ok(control_error(status, &value))
        }
    }
}

fn object_schema(properties: Map<String, Value>, required: Vec<Value>) -> Value {
    let mut schema = Map::from_iter([
        ("type".to_owned(), Value::String("object".to_owned())),
        ("properties".to_owned(), Value::Object(properties)),
        ("additionalProperties".to_owned(), Value::Bool(false)),
    ]);
    if !required.is_empty() {
        schema.insert("required".to_owned(), Value::Array(required));
    }
    Value::Object(schema)
}

fn schema_object(value: &Value, operation_id: &str, kind: &str) -> Result<JsonObject, String> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{operation_id} {kind} schema is not an object"))
}

fn resolve_schema(
    value: &Value,
    components: &Map<String, Value>,
    stack: &mut Vec<String>,
) -> Result<Value, String> {
    resolve_schema_at_instance(value, components, stack, true)
}

fn resolve_schema_at_instance(
    value: &Value,
    components: &Map<String, Value>,
    stack: &mut Vec<String>,
    close_object: bool,
) -> Result<Value, String> {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                let name = reference
                    .strip_prefix("#/components/schemas/")
                    .ok_or_else(|| format!("unsupported OpenAPI schema reference {reference}"))?;
                if stack.iter().any(|item| item == name) {
                    return Err(format!("recursive Control schema reference {name}"));
                }
                let referenced = components
                    .get(name)
                    .ok_or_else(|| format!("missing Control schema component {name}"))?;
                stack.push(name.to_owned());
                let mut resolved =
                    resolve_schema_at_instance(referenced, components, stack, close_object)?;
                stack.pop();
                if object.len() > 1 {
                    let resolved_object = resolved.as_object_mut().ok_or_else(|| {
                        format!("referenced Control schema {name} is not an object")
                    })?;
                    for (key, value) in object {
                        if key != "$ref" {
                            resolved_object.insert(
                                key.clone(),
                                resolve_schema_at_instance(value, components, stack, true)?,
                            );
                        }
                    }
                }
                return Ok(resolved);
            }
            let mut resolved = Map::new();
            for (key, value) in object {
                let close_child_object = match key.as_str() {
                    "allOf" => false,
                    "anyOf" | "oneOf" => close_object,
                    _ => true,
                };
                resolved.insert(
                    key.clone(),
                    resolve_schema_at_instance(value, components, stack, close_child_object)?,
                );
            }
            if close_object
                && resolved.get("type") == Some(&Value::String("object".to_owned()))
                && resolved.contains_key("properties")
            {
                resolved
                    .entry("additionalProperties")
                    .or_insert(Value::Bool(false));
            }
            Ok(Value::Object(resolved))
        }
        Value::Array(values) => values
            .iter()
            .map(|value| resolve_schema_at_instance(value, components, stack, close_object))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Ok(value.clone()),
    }
}

fn success_response(operation: &Value) -> Option<&Value> {
    operation
        .get("responses")?
        .as_object()?
        .iter()
        .filter(|(status, _)| status.starts_with('2'))
        .min_by_key(|(status, _)| *status)
        .map(|(_, response)| response)
}

fn success_output_schema(
    operation: &Value,
    components: &Map<String, Value>,
) -> Result<Value, String> {
    let Some(schema) = success_response(operation)
        .and_then(|response| response.pointer("/content/application~1json/schema"))
    else {
        return Ok(json!({ "type": "object", "additionalProperties": false }));
    };
    let mut schema = resolve_schema(schema, components, &mut Vec::new())?;
    let object = schema
        .as_object_mut()
        .ok_or_else(|| "Control success output schema is not an object".to_owned())?;
    match object.get("type") {
        Some(Value::String(kind)) if kind == "object" => {}
        None if object.contains_key("allOf") => {
            object.insert("type".to_owned(), Value::String("object".to_owned()));
        }
        _ => return Err("Control success output schema is not object-typed".to_owned()),
    }
    Ok(schema)
}

fn operation_title(operation_id: &str) -> String {
    operation_id
        .split('_')
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(characters).collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_read_only_operation(method: &Method, operation_id: &str) -> bool {
    method == Method::GET
        || matches!(
            operation_id,
            "preflight_oidc_provider" | "preflight_named_provider"
        )
}

fn is_destructive_operation(operation_id: &str) -> bool {
    !matches!(
        operation_id,
        "create_project"
            | "create_project_server_key"
            | "create_application"
            | "create_webhook_endpoint"
            | "prepare_webhook_secret_rotation"
            | "replay_webhook_delivery"
            | "create_provider"
            | "assign_provider"
            | "assign_email_method"
            | "create_smtp_configuration"
            | "test_smtp_configuration"
            | "create_managed_reauthorization"
            | "create_identity_mutation_intent"
    )
}

fn is_open_world_operation(operation_id: &str) -> bool {
    matches!(
        operation_id,
        "create_provider"
            | "preflight_oidc_provider"
            | "replay_webhook_delivery"
            | "synchronize_managed_provider_connection"
            | "test_webhook_endpoint"
            | "test_smtp_configuration"
    )
}

fn scalar_string(value: &Value) -> Option<Cow<'_, str>> {
    match value {
        Value::String(value) => Some(Cow::Borrowed(value)),
        Value::Number(value) => Some(Cow::Owned(value.to_string())),
        Value::Bool(value) => Some(Cow::Borrowed(if *value { "true" } else { "false" })),
        _ => None,
    }
}

fn tool_error(code: &str, message: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(
        json!({
            "error": {
                "code": code,
                "message": message
            }
        })
        .to_string(),
    )])
}

fn invalid_arguments(message: &str) -> CallToolResult {
    tool_error("invalid_arguments", message)
}

fn control_error(status: StatusCode, value: &Value) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(
        json!({
            "error": value,
            "http_status": status.as_u16()
        })
        .to_string(),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_catalog_covers_every_non_hand_designed_control_operation() {
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        assert_eq!(catalog.tools.len() + HAND_DESIGNED_OPERATION_IDS.len(), 87);
        assert!(catalog.contains("owlauth_create_project"));
        assert!(catalog.contains("owlauth_update_project"));
        assert!(catalog.contains("owlauth_enable_project"));
        assert!(catalog.contains("owlauth_delete_project"));
        assert!(catalog.contains("owlauth_create_provider"));
        assert!(catalog.contains("owlauth_create_project_server_key"));
        assert!(catalog.contains("owlauth_confirm_identity_mutation_intent"));
        for tool in catalog.tools.iter() {
            assert_eq!(
                tool.output_schema.as_ref().unwrap().get("type"),
                Some(&json!("object")),
                "{} has a non-object output schema",
                tool.name
            );
        }
        for tools in catalog.tools.chunks(super::super::TOOL_PAGE_SIZE) {
            let encoded = serde_json::to_vec(tools).unwrap();
            assert!(
                encoded.len() < 48_000,
                "generated MCP tool page is {} bytes",
                encoded.len()
            );
        }
    }

    #[test]
    fn generated_mutation_schema_carries_path_body_and_idempotency() {
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let tool = catalog.get_tool("owlauth_create_provider").unwrap();
        let schema = Value::Object(tool.input_schema.as_ref().clone());
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"]["project_id"].is_object());
        assert!(schema["properties"]["idempotency_key"].is_object());
        assert!(schema["properties"]["body"]["properties"]["client_secret"].is_object());
        let annotations = tool.annotations.unwrap();
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.open_world_hint, Some(true));
    }

    #[test]
    fn generated_annotations_distinguish_additive_destructive_and_external_operations() {
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let annotations = |name: &str| catalog.get_tool(name).unwrap().annotations.unwrap();

        let create = annotations("owlauth_create_application");
        assert_eq!(create.read_only_hint, Some(false));
        assert_eq!(create.destructive_hint, Some(false));
        assert_eq!(create.open_world_hint, Some(false));

        let disable = annotations("owlauth_disable_application");
        assert_eq!(disable.read_only_hint, Some(false));
        assert_eq!(disable.destructive_hint, Some(true));

        let enable_project = annotations("owlauth_enable_project");
        assert_eq!(enable_project.read_only_hint, Some(false));
        assert_eq!(enable_project.destructive_hint, Some(true));
        assert_eq!(enable_project.idempotent_hint, Some(false));

        let delete_project = annotations("owlauth_delete_project");
        assert_eq!(delete_project.read_only_hint, Some(false));
        assert_eq!(delete_project.destructive_hint, Some(true));
        assert_eq!(delete_project.idempotent_hint, Some(true));
        assert_eq!(delete_project.open_world_hint, Some(false));

        let delete_schema = Value::Object(
            catalog
                .get_tool("owlauth_delete_project")
                .unwrap()
                .input_schema
                .as_ref()
                .clone(),
        );
        assert_eq!(delete_schema["additionalProperties"], false);
        assert_eq!(
            delete_schema["properties"]["body"]["additionalProperties"],
            false
        );
        assert_eq!(
            delete_schema["properties"]["body"]["required"],
            json!(["expected_security_revision"])
        );

        let oidc = annotations("owlauth_preflight_oidc_provider");
        assert_eq!(oidc.read_only_hint, Some(true));
        assert_eq!(oidc.destructive_hint, Some(false));
        assert_eq!(oidc.open_world_hint, Some(true));

        let named = annotations("owlauth_preflight_named_provider");
        assert_eq!(named.read_only_hint, Some(true));
        assert_eq!(named.destructive_hint, Some(false));
        assert_eq!(named.open_world_hint, Some(false));
    }

    #[test]
    fn composed_output_schemas_do_not_close_individual_all_of_branches() {
        fn assert_all_of_branches_are_open(value: &Value, extends_same_instance: bool) {
            match value {
                Value::Object(object) => {
                    if extends_same_instance && object.get("type") == Some(&json!("object")) {
                        assert_ne!(object.get("additionalProperties"), Some(&json!(false)));
                    }
                    for (key, value) in object {
                        let child_extends_same_instance = match key.as_str() {
                            "allOf" => true,
                            "anyOf" | "oneOf" => extends_same_instance,
                            _ => false,
                        };
                        assert_all_of_branches_are_open(value, child_extends_same_instance);
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        assert_all_of_branches_are_open(value, extends_same_instance);
                    }
                }
                _ => {}
            }
        }

        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        for name in [
            "owlauth_create_identity_mutation_intent",
            "owlauth_create_managed_reauthorization",
            "owlauth_list_project_user_identities",
        ] {
            let schema = Value::Object(
                catalog
                    .get_tool(name)
                    .unwrap()
                    .output_schema
                    .unwrap()
                    .as_ref()
                    .clone(),
            );
            assert_eq!(schema["type"], "object");
            assert!(schema.to_string().contains("allOf"));
            assert_all_of_branches_are_open(&schema, false);
        }
    }

    #[test]
    fn generated_argument_errors_have_no_success_structured_content() {
        let result = serde_json::to_value(invalid_arguments("unknown argument")).unwrap();
        assert_eq!(result["isError"], true);
        assert!(result.get("structuredContent").is_none());
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("invalid_arguments")
        );
    }

    #[test]
    fn generated_read_schema_preserves_bounded_query_contract() {
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let tool = catalog
            .get_tool("owlauth_list_application_user_events")
            .unwrap();
        let schema = Value::Object(tool.input_schema.as_ref().clone());
        assert_eq!(schema["properties"]["limit"]["maximum"], 100);
        assert_eq!(tool.annotations.unwrap().read_only_hint, Some(true));
    }

    #[tokio::test]
    async fn generated_mutation_dispatches_method_path_header_and_body_to_control() {
        use axum::{Json, extract::Path, routing::post};

        let api = Router::new().route(
            "/v1/projects/{project_id}/providers",
            post(
                |Path(project_id): Path<String>,
                 headers: axum::http::HeaderMap,
                 Json(body): Json<Value>| async move {
                    Json(json!({
                        "project_id": project_id,
                        "content_type": headers
                            .get(header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok()),
                        "idempotency_key": headers
                            .get("idempotency-key")
                            .and_then(|value| value.to_str().ok()),
                        "body": body
                    }))
                },
            ),
        );
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let result = catalog
            .call(
                api,
                "owlauth_create_provider",
                Some(Map::from_iter([
                    (
                        "project_id".to_owned(),
                        json!("00000000-0000-0000-0000-000000000001"),
                    ),
                    ("idempotency_key".to_owned(), json!("provider-create-1")),
                    (
                        "body".to_owned(),
                        json!({
                            "provider_key": "example",
                            "client_secret": "write-only-secret"
                        }),
                    ),
                ])),
                4096,
            )
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(
            result["structuredContent"]["project_id"],
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            result["structuredContent"]["content_type"],
            "application/json"
        );
        assert_eq!(
            result["structuredContent"]["idempotency_key"],
            "provider-create-1"
        );
        assert_eq!(
            result["structuredContent"]["body"]["provider_key"],
            "example"
        );
    }

    #[tokio::test]
    async fn generated_dispatch_percent_encodes_paths_and_query_values() {
        use axum::{Json, http::Uri};

        let api = Router::new()
            .fallback(|uri: Uri| async move { Json(json!({ "uri": uri.to_string() })) });
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let result = catalog
            .call(
                api,
                "owlauth_list_application_user_events",
                Some(Map::from_iter([
                    ("project_id".to_owned(), json!("project/one")),
                    ("application_id".to_owned(), json!("application ?#")),
                    ("cursor".to_owned(), json!("next /?&=")),
                    ("limit".to_owned(), json!(25)),
                ])),
                4096,
            )
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        let uri = result["structuredContent"]["uri"].as_str().unwrap();
        assert!(uri.starts_with(
            "/v1/projects/project%2Fone/applications/application%20%3F%23/user-events?"
        ));
        let parsed = Url::parse(&format!("http://owlauth.internal{uri}")).unwrap();
        let query = parsed.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(query.get("cursor").map(Cow::as_ref), Some("next /?&="));
        assert_eq!(query.get("limit").map(Cow::as_ref), Some("25"));
    }

    #[tokio::test]
    async fn generated_dispatch_rejects_dot_path_segments_before_routing() {
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        for endpoint_id in [".", ".."] {
            let result = catalog
                .call(
                    Router::new(),
                    "owlauth_get_webhook_endpoint",
                    Some(Map::from_iter([
                        ("project_id".to_owned(), json!("project-1")),
                        ("application_id".to_owned(), json!("application-1")),
                        ("endpoint_id".to_owned(), json!(endpoint_id)),
                    ])),
                    4096,
                )
                .await
                .unwrap();
            let result = serde_json::to_value(result).unwrap();
            assert_eq!(result["isError"], true);
            assert!(result.get("structuredContent").is_none());
            assert!(
                result["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("must not be a dot segment")
            );
        }
    }

    #[tokio::test]
    async fn generated_control_errors_are_unstructured_tool_errors() {
        use axum::{Json, routing::post};

        let api = Router::new().route(
            "/v1/projects",
            post(|| async {
                (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "type": "about:blank",
                        "title": "Conflict",
                        "status": 409,
                        "code": "revision_conflict"
                    })),
                )
            }),
        );
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let result = catalog
            .call(
                api,
                "owlauth_create_project",
                Some(Map::from_iter([
                    ("idempotency_key".to_owned(), json!("project-create-1")),
                    ("body".to_owned(), json!({ "display_name": "Example" })),
                ])),
                4096,
            )
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["isError"], true);
        assert!(result.get("structuredContent").is_none());
        let error: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["http_status"], 409);
        assert_eq!(error["error"]["code"], "revision_conflict");
    }

    #[tokio::test]
    async fn generated_oversized_results_are_unstructured_tool_errors() {
        use axum::{Json, routing::post};

        let api = Router::new().route(
            "/v1/projects",
            post(|| async { Json(json!({ "value": "x".repeat(256) })) }),
        );
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let result = catalog
            .call(
                api,
                "owlauth_create_project",
                Some(Map::from_iter([
                    ("idempotency_key".to_owned(), json!("project-create-1")),
                    ("body".to_owned(), json!({ "display_name": "Example" })),
                ])),
                32,
            )
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["isError"], true);
        assert!(result.get("structuredContent").is_none());
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("result_too_large")
        );
    }

    #[tokio::test]
    async fn generated_server_key_creation_preserves_one_time_credential_result() {
        use axum::{Json, extract::Path, routing::post};

        let api = Router::new().route(
            "/v1/projects/{project_id}/server-keys",
            post(|Path(project_id): Path<String>| async move {
                (
                    StatusCode::CREATED,
                    Json(json!({
                        "key": {
                            "id": "key-1",
                            "project_id": project_id,
                            "label": "backend"
                        },
                        "credential": "owsk_one_time_secret"
                    })),
                )
            }),
        );
        let catalog = ControlToolCatalog::from_control_openapi().unwrap();
        let result = catalog
            .call(
                api,
                "owlauth_create_project_server_key",
                Some(Map::from_iter([
                    ("project_id".to_owned(), json!("project-1")),
                    ("idempotency_key".to_owned(), json!("server-key-create-1")),
                    ("body".to_owned(), json!({ "label": "backend" })),
                ])),
                4096,
            )
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(
            result["structuredContent"]["credential"],
            "owsk_one_time_secret"
        );
        assert_eq!(result["isError"], false);
    }
}
