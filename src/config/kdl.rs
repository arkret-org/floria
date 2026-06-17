use anyhow::{Result, anyhow};
use kdl::{KdlDocument, KdlNode, KdlValue};
use serde_json::{Map, Value};

// --- KDL support ---

pub(super) fn parse_kdl_to_json(body: &str) -> Result<Value> {
    let doc: KdlDocument = body.parse().map_err(|e: kdl::KdlError| anyhow!("{e}"))?;
    Ok(kdl_document_to_json(&doc))
}

fn kdl_document_to_json(doc: &KdlDocument) -> Value {
    let mut map = Map::new();
    for node in doc.nodes() {
        let name = node.name().value().to_string();
        let value = kdl_node_to_json_value(node);
        map.insert(name, value);
    }
    Value::Object(map)
}

fn kdl_node_to_json_value(node: &KdlNode) -> Value {
    let positional: Vec<_> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect();

    match node.children() {
        // All children named `-` → array (KDL array convention).
        Some(children)
            if !children.nodes().is_empty()
                && children.nodes().iter().all(|n| n.name().value() == "-") =>
        {
            Value::Array(
                children
                    .nodes()
                    .iter()
                    .map(kdl_node_to_json_value)
                    .collect(),
            )
        }
        // Children block → object.
        Some(children) => {
            let mut obj = Map::new();
            for child in children.nodes() {
                obj.insert(
                    child.name().value().to_string(),
                    kdl_node_to_json_value(child),
                );
            }
            Value::Object(obj)
        }
        // Single positional argument → scalar.
        None if positional.len() == 1 => kdl_scalar_to_json(positional[0].value()),
        // Multiple positional arguments → array.
        None if positional.len() > 1 => Value::Array(
            positional
                .iter()
                .map(|e| kdl_scalar_to_json(e.value()))
                .collect(),
        ),
        // No arguments, no children → null.
        None => Value::Null,
    }
}

fn kdl_scalar_to_json(value: &KdlValue) -> Value {
    match value {
        KdlValue::String(s) => Value::String(s.clone()),
        KdlValue::Integer(n) => {
            if let Ok(n) = i64::try_from(*n) {
                Value::Number(n.into())
            } else {
                Value::Null
            }
        }
        KdlValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        KdlValue::Bool(b) => Value::Bool(*b),
        KdlValue::Null => Value::Null,
    }
}
