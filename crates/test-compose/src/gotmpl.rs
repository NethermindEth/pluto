//! Interpreter for the subset of Go `text/template` syntax used by the
//! compose templates.
//!
//! Supported: literal text, `{{.}}`, `{{.Field.Chain}}`, `{{$var.Field}}`,
//! `{{if pipeline}}…{{end}}`, `{{range pipeline}}…{{end}}`,
//! `{{range $elem := pipeline}}`, `{{range $idx, $elem := pipeline}}` and the
//! `{{- ` / ` -}}` whitespace trim markers, all with Go's semantics.
//!
//! Everything else (`else`, `with`, `define`, functions, pipes, literals,
//! comparisons) is rejected while parsing so that a template edit relying on
//! an unimplemented construct fails loudly instead of rendering wrongly.

use std::{iter::Peekable, vec::IntoIter};

/// The whitespace characters stripped by the trim markers.
const SPACE_CHARS: &[char] = &[' ', '\t', '\r', '\n'];

/// Template parse or execution error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// An action opened with `{{` was never closed.
    #[error("unclosed action at byte {offset}")]
    UnclosedAction {
        /// Byte offset of the `{{`.
        offset: usize,
    },

    /// The action uses a construct this interpreter does not implement.
    #[error("unsupported template action at byte {offset}: {{{{{action}}}}}")]
    Unsupported {
        /// Byte offset of the action.
        offset: usize,
        /// The trimmed action body.
        action: String,
    },

    /// `{{end}}` without a matching `if` or `range`.
    #[error("unexpected {{{{end}}}} at byte {offset}")]
    UnexpectedEnd {
        /// Byte offset of the action.
        offset: usize,
    },

    /// An `if` or `range` was never closed.
    #[error("missing {{{{end}}}} for {kind} at byte {offset}")]
    MissingEnd {
        /// Which construct is open.
        kind: &'static str,
        /// Byte offset of the opening action.
        offset: usize,
    },

    /// A token is not a field chain or variable reference.
    #[error("bad operand: {token}")]
    BadOperand {
        /// The offending token.
        token: String,
    },

    /// Field access on a value without that field.
    #[error("can't evaluate field {field} in {kind}")]
    NoField {
        /// The requested field.
        field: String,
        /// The kind of value it was requested on.
        kind: &'static str,
    },

    /// A `$var` that is not in scope.
    #[error("undefined variable: ${name}")]
    UndefinedVariable {
        /// The variable name without the `$`.
        name: String,
    },

    /// `range` over a value that is not a list.
    #[error("range can't iterate over {kind}")]
    NotIterable {
        /// The kind of value ranged over.
        kind: &'static str,
    },

    /// Printing a value that has no textual form.
    #[error("can't print {kind}")]
    NotPrintable {
        /// The kind of value printed.
        kind: &'static str,
    },

    /// A range index does not fit the template integer type.
    #[error("range index overflow")]
    IndexOverflow,
}

/// A value the template can evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A string, printed verbatim.
    Str(String),
    /// A signed integer.
    Int(i64),
    /// A boolean, printed as `true` / `false`.
    Bool(bool),
    /// A list, iterable with `range`.
    List(Vec<Value>),
    /// A struct-like value with named fields.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Builds an object from `(field, value)` pairs.
    pub fn object<K: Into<String>>(fields: impl IntoIterator<Item = (K, Value)>) -> Self {
        Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Builds a string value.
    pub fn str(value: impl Into<String>) -> Self {
        Value::Str(value.into())
    }

    /// Builds a list of string values.
    pub fn str_list<S: Into<String>>(items: impl IntoIterator<Item = S>) -> Self {
        Value::List(items.into_iter().map(Value::str).collect())
    }

    fn kind(&self) -> &'static str {
        match self {
            Value::Str(_) => "string",
            Value::Int(_) => "int",
            Value::Bool(_) => "bool",
            Value::List(_) => "list",
            Value::Object(_) => "object",
        }
    }

    fn field(&self, name: &str) -> Result<&Value, Error> {
        if let Value::Object(fields) = self
            && let Some((_, value)) = fields.iter().find(|(k, _)| k == name)
        {
            return Ok(value);
        }

        Err(Error::NoField {
            field: name.to_string(),
            kind: self.kind(),
        })
    }

    /// Go truthiness: false, zero, empty string and empty list are false.
    fn truthy(&self) -> bool {
        match self {
            Value::Str(s) => !s.is_empty(),
            Value::Int(i) => *i != 0,
            Value::Bool(b) => *b,
            Value::List(l) => !l.is_empty(),
            Value::Object(_) => true,
        }
    }

    fn print(&self, out: &mut String) -> Result<(), Error> {
        match self {
            Value::Str(s) => out.push_str(s),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::List(_) | Value::Object(_) => {
                return Err(Error::NotPrintable { kind: self.kind() });
            }
        }

        Ok(())
    }
}

/// What an operand starts from: the current dot or a `$variable`.
#[derive(Debug)]
enum Base {
    Dot,
    Var(String),
}

/// A field chain rooted at dot or a variable, e.g. `.Nodes`, `$vc.Label`, `.`.
#[derive(Debug)]
struct Operand {
    base: Base,
    path: Vec<String>,
}

#[derive(Debug)]
enum Node {
    Text(String),
    Print(Operand),
    If {
        cond: Operand,
        body: Vec<Node>,
    },
    Range {
        index_var: Option<String>,
        elem_var: Option<String>,
        over: Operand,
        body: Vec<Node>,
    },
}

#[derive(Debug)]
enum Token {
    Text(String),
    Action { body: String, offset: usize },
}

/// A parsed template.
#[derive(Debug)]
pub struct Template {
    nodes: Vec<Node>,
}

impl Template {
    /// Parses template source, rejecting unsupported constructs.
    pub fn parse(src: &str) -> Result<Self, Error> {
        let tokens = lex(src)?;
        let mut tokens = tokens.into_iter().peekable();
        let nodes = parse_nodes(&mut tokens, None)?;

        Ok(Self { nodes })
    }

    /// Renders the template with `dot` as the root value.
    pub fn execute(&self, dot: &Value) -> Result<String, Error> {
        let mut out = String::new();
        let mut vars = Vec::new();
        exec(&self.nodes, dot, &mut vars, &mut out)?;

        Ok(out)
    }
}

fn is_space(c: char) -> bool {
    SPACE_CHARS.contains(&c)
}

fn lex(src: &str) -> Result<Vec<Token>, Error> {
    let mut tokens = Vec::new();
    let mut rest = src;
    let mut pos = 0usize;
    let mut trim_next = false;

    loop {
        let Some(open) = rest.find("{{") else {
            push_text(&mut tokens, rest, trim_next, false);
            break;
        };

        let text = rest.get(..open).unwrap_or_default();
        let after = rest.get(open.saturating_add(2)..).unwrap_or_default();

        // `{{- ` (dash followed by a space) trims the preceding text.
        let trim_left =
            after.starts_with('-') && after.get(1..).is_some_and(|s| s.starts_with(is_space));
        push_text(&mut tokens, text, trim_next, trim_left);

        let body_skip = if trim_left { 2 } else { 0 };
        let body_rest = after.get(body_skip..).unwrap_or_default();
        let action_offset = pos.saturating_add(open);

        let Some(close) = body_rest.find("}}") else {
            return Err(Error::UnclosedAction {
                offset: action_offset,
            });
        };

        let mut body = body_rest.get(..close).unwrap_or_default();

        // ` -}}` (space followed by dash) trims the following text.
        let trim_right = body.ends_with('-')
            && body
                .get(..body.len().saturating_sub(1))
                .is_some_and(|s| s.ends_with(is_space));
        if trim_right {
            body = body.get(..body.len().saturating_sub(2)).unwrap_or_default();
        }

        tokens.push(Token::Action {
            body: body.trim_matches(is_space).to_string(),
            offset: action_offset,
        });
        trim_next = trim_right;

        let consumed = open
            .saturating_add(2)
            .saturating_add(body_skip)
            .saturating_add(close)
            .saturating_add(2);
        pos = pos.saturating_add(consumed);
        rest = rest.get(consumed..).unwrap_or_default();
    }

    Ok(tokens)
}

fn push_text(tokens: &mut Vec<Token>, text: &str, trim_start: bool, trim_end: bool) {
    let mut text = text;
    if trim_start {
        text = text.trim_start_matches(is_space);
    }
    if trim_end {
        text = text.trim_end_matches(is_space);
    }
    if !text.is_empty() {
        tokens.push(Token::Text(text.to_string()));
    }
}

fn parse_nodes(
    tokens: &mut Peekable<IntoIter<Token>>,
    open: Option<(&'static str, usize)>,
) -> Result<Vec<Node>, Error> {
    let mut nodes = Vec::new();

    while let Some(token) = tokens.next() {
        let (body, offset) = match token {
            Token::Text(text) => {
                nodes.push(Node::Text(text));
                continue;
            }
            Token::Action { body, offset } => (body, offset),
        };

        // Commas are their own tokens in Go's lexer (`$i, $node`).
        let spaced = body.replace(',', " , ");
        let words: Vec<&str> = spaced.split_whitespace().collect();
        let unsupported = || Error::Unsupported {
            offset,
            action: body.clone(),
        };

        match words.as_slice() {
            ["end"] => {
                return match open {
                    Some(_) => Ok(nodes),
                    None => Err(Error::UnexpectedEnd { offset }),
                };
            }
            ["if", cond] => {
                let cond = parse_operand(cond)?;
                let body = parse_nodes(tokens, Some(("if", offset)))?;
                nodes.push(Node::If { cond, body });
            }
            ["range", over] => {
                let over = parse_operand(over)?;
                let body = parse_nodes(tokens, Some(("range", offset)))?;
                nodes.push(Node::Range {
                    index_var: None,
                    elem_var: None,
                    over,
                    body,
                });
            }
            ["range", elem, ":=", over] => {
                let elem_var = Some(parse_var_decl(elem)?);
                let over = parse_operand(over)?;
                let body = parse_nodes(tokens, Some(("range", offset)))?;
                nodes.push(Node::Range {
                    index_var: None,
                    elem_var,
                    over,
                    body,
                });
            }
            ["range", index, ",", elem, ":=", over] => {
                let index_var = Some(parse_var_decl(index)?);
                let elem_var = Some(parse_var_decl(elem)?);
                let over = parse_operand(over)?;
                let body = parse_nodes(tokens, Some(("range", offset)))?;
                nodes.push(Node::Range {
                    index_var,
                    elem_var,
                    over,
                    body,
                });
            }
            [
                "if" | "range" | "end" | "else" | "with" | "define" | "template" | "block"
                | "break" | "continue" | "nil",
                ..,
            ] => return Err(unsupported()),
            [single] => nodes.push(Node::Print(parse_operand(single)?)),
            _ => return Err(unsupported()),
        }
    }

    match open {
        Some((kind, offset)) => Err(Error::MissingEnd { kind, offset }),
        None => Ok(nodes),
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parses `$name` in a range declaration.
fn parse_var_decl(token: &str) -> Result<String, Error> {
    match token.strip_prefix('$') {
        Some(name) if is_ident(name) => Ok(name.to_string()),
        _ => Err(Error::BadOperand {
            token: token.to_string(),
        }),
    }
}

fn parse_operand(token: &str) -> Result<Operand, Error> {
    let bad = || Error::BadOperand {
        token: token.to_string(),
    };

    if token == "." {
        return Ok(Operand {
            base: Base::Dot,
            path: Vec::new(),
        });
    }

    if let Some(chain) = token.strip_prefix('.') {
        let path: Vec<String> = chain.split('.').map(str::to_string).collect();
        if !path.iter().all(|p| is_ident(p)) {
            return Err(bad());
        }

        return Ok(Operand {
            base: Base::Dot,
            path,
        });
    }

    if let Some(var) = token.strip_prefix('$') {
        let mut parts = var.split('.');
        let name = parts.next().unwrap_or_default();
        if !is_ident(name) {
            return Err(bad());
        }

        let path: Vec<String> = parts.map(str::to_string).collect();
        if !path.iter().all(|p| is_ident(p)) {
            return Err(bad());
        }

        return Ok(Operand {
            base: Base::Var(name.to_string()),
            path,
        });
    }

    Err(bad())
}

fn eval<'v>(
    operand: &Operand,
    dot: &'v Value,
    vars: &'v [(String, Value)],
) -> Result<&'v Value, Error> {
    let mut value = match &operand.base {
        Base::Dot => dot,
        Base::Var(name) => {
            let Some((_, value)) = vars.iter().rev().find(|(k, _)| k == name) else {
                return Err(Error::UndefinedVariable { name: name.clone() });
            };
            value
        }
    };

    for field in &operand.path {
        value = value.field(field)?;
    }

    Ok(value)
}

fn exec(
    nodes: &[Node],
    dot: &Value,
    vars: &mut Vec<(String, Value)>,
    out: &mut String,
) -> Result<(), Error> {
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Print(operand) => eval(operand, dot, vars)?.print(out)?,
            Node::If { cond, body } => {
                if eval(cond, dot, vars)?.truthy() {
                    exec(body, dot, vars, out)?;
                }
            }
            Node::Range {
                index_var,
                elem_var,
                over,
                body,
            } => {
                let items = match eval(over, dot, vars)? {
                    Value::List(items) => items.clone(),
                    other => return Err(Error::NotIterable { kind: other.kind() }),
                };

                for (i, item) in items.iter().enumerate() {
                    let depth = vars.len();
                    if let Some(name) = index_var {
                        let index = i64::try_from(i).map_err(|_| Error::IndexOverflow)?;
                        vars.push((name.clone(), Value::Int(index)));
                    }
                    if let Some(name) = elem_var {
                        vars.push((name.clone(), item.clone()));
                    }

                    exec(body, item, vars, out)?;
                    vars.truncate(depth);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    fn render(src: &str, dot: &Value) -> Result<String, Error> {
        Template::parse(src)?.execute(dot)
    }

    fn sample() -> Value {
        Value::object([
            ("Name", Value::str("compose")),
            ("Empty", Value::str("")),
            ("Yes", Value::Bool(true)),
            ("No", Value::Bool(false)),
            ("Zero", Value::Int(0)),
            ("Count", Value::Int(3)),
            ("None", Value::List(vec![])),
            ("Items", Value::str_list(["a", "b"])),
            (
                "Nodes",
                Value::List(vec![
                    Value::object([
                        ("Label", Value::str("x")),
                        ("Ports", Value::str_list(["1", "2"])),
                    ]),
                    Value::object([("Label", Value::str("")), ("Ports", Value::List(vec![]))]),
                ]),
            ),
        ])
    }

    #[test_case("plain text", "plain text" ; "text_only")]
    #[test_case("a {{.Name}} b", "a compose b" ; "field")]
    #[test_case("{{ .Name }}", "compose" ; "inner_padding")]
    #[test_case("{{.Count}}/{{.Yes}}/{{.No}}", "3/true/false" ; "int_and_bool")]
    #[test_case("[{{if .Name}}y{{end}}]", "[y]" ; "if_string_true")]
    #[test_case("[{{if .Empty}}y{{end}}]", "[]" ; "if_string_false")]
    #[test_case("[{{if .Yes}}y{{end}}][{{if .No}}n{{end}}]", "[y][]" ; "if_bool")]
    #[test_case("[{{if .Zero}}y{{end}}][{{if .Count}}c{{end}}]", "[][c]" ; "if_int")]
    #[test_case("[{{if .None}}y{{end}}][{{if .Items}}i{{end}}]", "[][i]" ; "if_list")]
    #[test_case("{{range .Items}}<{{.}}>{{end}}", "<a><b>" ; "range_dot")]
    #[test_case("{{range $v := .Items}}<{{$v}}>{{end}}", "<a><b>" ; "range_elem_var")]
    #[test_case("{{range $i, $v := .Items}}{{$i}}={{$v}};{{end}}", "0=a;1=b;" ; "range_index_var")]
    #[test_case("{{range .None}}x{{end}}-", "-" ; "range_empty")]
    #[test_case(
        "{{range $i, $n := .Nodes}}{{$i}}:{{$n.Label}}{{if $n.Ports}}[{{range $n.Ports}}{{.}}{{end}}]{{end}};{{end}}",
        "0:x[12];1:;" ; "nested_range_and_var_fields"
    )]
    #[test_case("a  \n  {{- .Name}}", "acompose" ; "trim_left")]
    #[test_case("{{.Name -}}  \n\n b", "composeb" ; "trim_right")]
    #[test_case("x\n  {{- if .Yes}}\n  y\n  {{end -}}\n  z", "x\n  y\n  z" ; "trim_both_sides_of_block")]
    #[test_case("{{if .Yes -}}\n  a\n{{- end}}", "a" ; "trim_inside_block")]
    fn renders(src: &str, want: &str) {
        assert_eq!(render(src, &sample()), Ok(want.to_string()));
    }

    #[test]
    fn dash_without_space_keeps_text() {
        // `{{-` without a following space is not a trim marker: the dash
        // belongs to the action and makes it an unsupported token.
        let err = render("a {{-x}}", &sample()).expect_err("must fail");
        assert!(matches!(err, Error::BadOperand { .. }), "{err:?}");
    }

    #[test_case("{{.Name", Error::UnclosedAction { offset: 0 } ; "unclosed")]
    #[test_case("a{{end}}", Error::UnexpectedEnd { offset: 1 } ; "stray_end")]
    #[test_case("{{if .Yes}}x", Error::MissingEnd { kind: "if", offset: 0 } ; "missing_end_if")]
    #[test_case("{{range .Items}}x", Error::MissingEnd { kind: "range", offset: 0 } ; "missing_end_range")]
    #[test_case("{{if .Yes}}a{{else}}b{{end}}", Error::Unsupported { offset: 12, action: "else".to_string() } ; "else_action")]
    #[test_case("{{with .Name}}{{end}}", Error::Unsupported { offset: 0, action: "with .Name".to_string() } ; "with")]
    #[test_case("{{.Name | printf}}", Error::Unsupported { offset: 0, action: ".Name | printf".to_string() } ; "pipe")]
    #[test_case("{{printf \"x\"}}", Error::Unsupported { offset: 0, action: "printf \"x\"".to_string() } ; "function")]
    #[test_case("{{if eq .Name \"x\"}}{{end}}", Error::Unsupported { offset: 0, action: "if eq .Name \"x\"".to_string() } ; "comparison")]
    #[test_case("{{range $i := }}{{end}}", Error::Unsupported { offset: 0, action: "range $i :=".to_string() } ; "bad_range_decl")]
    #[test_case("{{\"lit\"}}", Error::BadOperand { token: "\"lit\"".to_string() } ; "literal")]
    #[test_case("{{$}}", Error::BadOperand { token: "$".to_string() } ; "root_var")]
    #[test_case("{{.Missing}}", Error::NoField { field: "Missing".to_string(), kind: "object" } ; "missing_field")]
    #[test_case("{{.Name.Inner}}", Error::NoField { field: "Inner".to_string(), kind: "string" } ; "field_on_string")]
    #[test_case("{{$v}}", Error::UndefinedVariable { name: "v".to_string() } ; "undefined_var")]
    #[test_case("{{range .Name}}{{end}}", Error::NotIterable { kind: "string" } ; "range_string")]
    #[test_case("{{.Items}}", Error::NotPrintable { kind: "list" } ; "print_list")]
    #[test_case("{{.}}", Error::NotPrintable { kind: "object" } ; "print_object")]
    fn rejects(src: &str, want: Error) {
        assert_eq!(render(src, &sample()), Err(want));
    }

    #[test]
    fn variables_are_scoped_to_their_range() {
        let err = render("{{range $v := .Items}}{{end}}{{$v}}", &sample()).expect_err("must fail");
        assert_eq!(
            err,
            Error::UndefinedVariable {
                name: "v".to_string()
            }
        );
    }
}
