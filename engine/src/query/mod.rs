//! Shrike Query Language — a small, HTTPQL-inspired filter language for history.
//!
//! Grammar (own design; case-insensitive keywords):
//!   expr    := or
//!   or      := and ("OR" and)*
//!   and     := unary (("AND")? unary)*        // adjacency means AND
//!   unary   := "NOT" unary | primary
//!   primary := "(" or ")" | predicate
//!   predicate := FIELD OP VALUE | TERM        // a bare TERM searches url+host
//!
//! Fields → columns: host, method, code/status, url, path, mime/type, port,
//! len/size, body (searches the serialized transaction incl. bodies/headers).
//! Operators: `:` (contains for text / equals for numbers), `=`, `!=`, `>`,
//! `>=`, `<`, `<=`. Values may be quoted (`"..."`) or a bare word.
//!
//! It compiles to a parameterised SQL `WHERE` body (placeholders only — no value
//! is ever interpolated into SQL), returned with its bound values.

use rusqlite::types::Value;

/// Compile a query into an SQL boolean expression (without the `WHERE` keyword)
/// and its bound parameters. Empty input matches everything (`"1"`).
pub fn compile(input: &str) -> Result<(String, Vec<Value>), String> {
    let toks = tokenize(input)?;
    if toks.is_empty() {
        return Ok(("1".to_string(), vec![]));
    }
    let mut p = Parser {
        toks,
        pos: 0,
        params: Vec::new(),
    };
    let sql = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(format!(
            "unexpected trailing input near token {}",
            p.pos + 1
        ));
    }
    Ok((sql, p.params))
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Op(String),
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated quoted string".into());
                }
                i += 1; // closing quote
                toks.push(Tok::Str(s));
            }
            ':' | '=' => {
                toks.push(Tok::Op(c.to_string()));
                i += 1;
            }
            '!' | '>' | '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    toks.push(Tok::Op(format!("{c}=")));
                    i += 2;
                } else if c == '!' {
                    return Err("expected != ".into());
                } else {
                    toks.push(Tok::Op(c.to_string()));
                    i += 1;
                }
            }
            _ => {
                let mut w = String::new();
                while i < chars.len() {
                    let d = chars[i];
                    if d.is_whitespace()
                        || matches!(d, '(' | ')' | '"' | ':' | '=' | '>' | '<' | '!')
                    {
                        break;
                    }
                    w.push(d);
                    i += 1;
                }
                toks.push(Tok::Word(w));
            }
        }
    }
    Ok(toks)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    params: Vec<Value>,
}

fn is_kw(t: &Tok, kw: &str) -> bool {
    matches!(t, Tok::Word(w) if w.eq_ignore_ascii_case(kw))
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn parse_or(&mut self) -> Result<String, String> {
        let mut left = self.parse_and()?;
        while self.peek().is_some_and(|t| is_kw(t, "or")) {
            self.pos += 1;
            let right = self.parse_and()?;
            left = format!("({left} OR {right})");
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<String, String> {
        let mut left = self.parse_unary()?;
        loop {
            match self.peek() {
                None => break,
                Some(t) if matches!(t, Tok::RParen) || is_kw(t, "or") => break,
                Some(t) if is_kw(t, "and") => {
                    self.pos += 1;
                }
                _ => {} // adjacency = implicit AND
            }
            let right = self.parse_unary()?;
            left = format!("({left} AND {right})");
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<String, String> {
        if self.peek().is_some_and(|t| is_kw(t, "not")) {
            self.pos += 1;
            let inner = self.parse_unary()?;
            return Ok(format!("(NOT {inner})"));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<String, String> {
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.pos += 1;
                let inner = self.parse_or()?;
                match self.peek() {
                    Some(Tok::RParen) => {
                        self.pos += 1;
                        Ok(inner)
                    }
                    _ => Err("expected ')'".into()),
                }
            }
            Some(Tok::Word(w)) => {
                self.pos += 1;
                // field OP value ?
                if let Some(Tok::Op(op)) = self.peek().cloned() {
                    self.pos += 1;
                    let val = match self.peek().cloned() {
                        Some(Tok::Word(v)) => {
                            self.pos += 1;
                            v
                        }
                        Some(Tok::Str(v)) => {
                            self.pos += 1;
                            v
                        }
                        _ => return Err(format!("expected a value after '{op}'")),
                    };
                    self.predicate(&w, &op, &val)
                } else {
                    Ok(self.bare_term(&w))
                }
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Ok(self.bare_term(&s))
            }
            Some(Tok::Op(op)) => Err(format!("unexpected operator '{op}'")),
            Some(Tok::RParen) => Err("unexpected ')'".into()),
            None => Err("unexpected end of query".into()),
        }
    }

    fn bare_term(&mut self, term: &str) -> String {
        let pat = Value::Text(format!("%{}%", like_escape(term)));
        self.params.push(pat.clone());
        self.params.push(pat);
        "(url LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\')".to_string()
    }

    fn predicate(&mut self, field: &str, op: &str, val: &str) -> Result<String, String> {
        let f = field.to_ascii_lowercase();
        // (column, is_numeric)
        let (col, numeric): (&str, bool) = match f.as_str() {
            "host" => ("host", false),
            "method" => ("method", false),
            "code" | "status" => ("status", true),
            "url" | "path" => ("url", false),
            "mime" | "type" => ("mime", false),
            "port" => ("port", true),
            "len" | "size" => ("resp_len", true),
            "body" => ("view_json", false),
            other => return Err(format!("unknown field '{other}'")),
        };

        if numeric {
            let n: i64 = val
                .parse()
                .map_err(|_| format!("'{field}' needs a number, got '{val}'"))?;
            let sql_op = match op {
                ":" | "=" => "=",
                "!=" => "!=",
                ">" => ">",
                ">=" => ">=",
                "<" => "<",
                "<=" => "<=",
                _ => return Err(format!("operator '{op}' is not valid for '{field}'")),
            };
            self.params.push(Value::Integer(n));
            return Ok(format!("{col} {sql_op} ?"));
        }

        // text field
        let v = if f == "method" {
            val.to_uppercase()
        } else {
            val.to_string()
        };
        match op {
            ":" => {
                self.params
                    .push(Value::Text(format!("%{}%", like_escape(&v))));
                Ok(format!("{col} LIKE ? ESCAPE '\\'"))
            }
            "=" => {
                self.params.push(Value::Text(v));
                Ok(format!("{col} = ?"))
            }
            "!=" => {
                self.params
                    .push(Value::Text(format!("%{}%", like_escape(&v))));
                Ok(format!("({col} IS NULL OR {col} NOT LIKE ? ESCAPE '\\')"))
            }
            _ => Err(format!(
                "operator '{op}' is not valid for text field '{field}'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n_params(input: &str) -> (String, usize) {
        let (sql, p) = compile(input).unwrap();
        (sql, p.len())
    }

    #[test]
    fn empty_matches_all() {
        assert_eq!(compile("").unwrap().0, "1");
    }

    #[test]
    fn simple_predicates_and_fields() {
        let (sql, n) = n_params("host:example.com");
        assert!(sql.contains("host LIKE ?"), "{sql}");
        assert_eq!(n, 1);

        assert!(compile("method=GET").unwrap().0.contains("method = ?"));
        assert!(compile("code>=400").unwrap().0.contains("status >= ?"));
        assert!(compile("port:8080").unwrap().0.contains("port = ?"));
        assert!(
            compile("body:password")
                .unwrap()
                .0
                .contains("view_json LIKE ?")
        );
    }

    #[test]
    fn boolean_precedence_and_grouping() {
        // implicit AND between adjacent terms, OR lower precedence
        let (sql, n) = n_params("host:a code:200 OR method:POST");
        assert_eq!(n, 3);
        // the AND binds tighter than OR
        assert!(sql.contains(" OR "), "{sql}");
        assert!(sql.contains(" AND "), "{sql}");

        let g = compile("(host:a OR host:b) code:500").unwrap().0;
        assert!(g.starts_with("(("), "grouping preserved: {g}");

        assert!(compile("NOT method:GET").unwrap().0.contains("NOT"));
    }

    #[test]
    fn method_value_is_uppercased() {
        let (_sql, params) = compile("method=get").unwrap();
        assert_eq!(params[0], Value::Text("GET".into()));
    }

    #[test]
    fn errors_are_reported() {
        assert!(compile("code:abc").is_err(), "non-numeric code");
        assert!(compile("bogus:1").is_err(), "unknown field");
        assert!(compile("(host:a").is_err(), "unbalanced paren");
        assert!(compile("host:").is_err(), "missing value");
        assert!(compile("\"unterminated").is_err());
    }
}
