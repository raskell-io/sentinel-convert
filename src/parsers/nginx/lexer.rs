//! nginx configuration lexer

use nom::{
    branch::alt,
    bytes::complete::{escaped, is_not, tag, take_until, take_while, take_while1},
    character::complete::{char, line_ending, multispace0, multispace1, none_of, one_of},
    combinator::{all_consuming, map, opt, recognize, value},
    multi::{many0, many1, separated_list0},
    sequence::{delimited, pair, preceded, terminated, tuple},
    IResult,
};

/// Token types for nginx config
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Identifier/directive name
    Identifier(String),
    /// String literal (quoted)
    String(String),
    /// Number
    Number(String),
    /// Open brace {
    OpenBrace,
    /// Close brace }
    CloseBrace,
    /// Semicolon ;
    Semicolon,
    /// Comment
    Comment(String),
    /// Newline (for tracking line numbers)
    Newline,
}

/// Tokenize nginx configuration
pub fn tokenize(input: &str) -> Result<Vec<(Token, usize)>, String> {
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut remaining = input;

    while !remaining.is_empty() {
        // Skip whitespace (except newlines)
        let (rest, _) = skip_horizontal_whitespace(remaining)
            .map_err(|e| format!("Whitespace error at line {}: {:?}", line, e))?;
        remaining = rest;

        if remaining.is_empty() {
            break;
        }

        // Check for newline
        if remaining.starts_with('\n') {
            remaining = &remaining[1..];
            line += 1;
            continue;
        }

        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
            line += 1;
            continue;
        }

        // Check for comment
        if remaining.starts_with('#') {
            let (rest, comment) = parse_comment(remaining)
                .map_err(|e| format!("Comment error at line {}: {:?}", line, e))?;
            tokens.push((Token::Comment(comment), line));
            remaining = rest;
            continue;
        }

        // Check for braces and semicolon
        if remaining.starts_with('{') {
            tokens.push((Token::OpenBrace, line));
            remaining = &remaining[1..];
            continue;
        }

        if remaining.starts_with('}') {
            tokens.push((Token::CloseBrace, line));
            remaining = &remaining[1..];
            continue;
        }

        if remaining.starts_with(';') {
            tokens.push((Token::Semicolon, line));
            remaining = &remaining[1..];
            continue;
        }

        // Check for quoted string
        if remaining.starts_with('"') || remaining.starts_with('\'') {
            let (rest, s) = parse_quoted_string(remaining)
                .map_err(|e| format!("String error at line {}: {:?}", line, e))?;
            tokens.push((Token::String(s), line));
            remaining = rest;
            continue;
        }

        // Parse identifier or number
        let (rest, word) = parse_word(remaining)
            .map_err(|e| format!("Word error at line {}: {:?}", line, e))?;

        if word.is_empty() {
            return Err(format!(
                "Unexpected character at line {}: {:?}",
                line,
                remaining.chars().next()
            ));
        }

        // Determine if it's a number or identifier
        if word.chars().all(|c| c.is_ascii_digit() || c == '.') {
            tokens.push((Token::Number(word), line));
        } else {
            tokens.push((Token::Identifier(word), line));
        }
        remaining = rest;
    }

    Ok(tokens)
}

fn skip_horizontal_whitespace(input: &str) -> IResult<&str, &str> {
    take_while(|c: char| c == ' ' || c == '\t')(input)
}

fn parse_comment(input: &str) -> IResult<&str, String> {
    let (rest, _) = char('#')(input)?;
    let (rest, comment) = take_while(|c: char| c != '\n' && c != '\r')(rest)?;
    Ok((rest, comment.to_string()))
}

fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    alt((parse_double_quoted, parse_single_quoted))(input)
}

fn parse_double_quoted(input: &str) -> IResult<&str, String> {
    let (rest, _) = char('"')(input)?;
    let mut result = String::new();
    let mut chars = rest.chars().peekable();
    let mut consumed = 0;

    while let Some(c) = chars.next() {
        consumed += c.len_utf8();
        match c {
            '"' => {
                return Ok((&rest[consumed..], result));
            }
            '\\' => {
                if let Some(&next) = chars.peek() {
                    consumed += next.len_utf8();
                    chars.next();
                    match next {
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        'r' => result.push('\r'),
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        _ => {
                            result.push('\\');
                            result.push(next);
                        }
                    }
                }
            }
            _ => result.push(c),
        }
    }

    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Char,
    )))
}

fn parse_single_quoted(input: &str) -> IResult<&str, String> {
    let (rest, _) = char('\'')(input)?;
    let mut result = String::new();
    let mut chars = rest.chars().peekable();
    let mut consumed = 0;

    while let Some(c) = chars.next() {
        consumed += c.len_utf8();
        match c {
            '\'' => {
                return Ok((&rest[consumed..], result));
            }
            '\\' => {
                if let Some(&next) = chars.peek() {
                    consumed += next.len_utf8();
                    chars.next();
                    if next == '\'' {
                        result.push('\'');
                    } else {
                        result.push('\\');
                        result.push(next);
                    }
                }
            }
            _ => result.push(c),
        }
    }

    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Char,
    )))
}

fn parse_word(input: &str) -> IResult<&str, String> {
    let (rest, word) = take_while1(|c: char| {
        !c.is_whitespace() && c != '{' && c != '}' && c != ';' && c != '#' && c != '"' && c != '\''
    })(input)?;
    Ok((rest, word.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_simple() {
        let input = "worker_processes 4;";
        let tokens = tokenize(input).unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].0, Token::Identifier("worker_processes".to_string()));
        assert_eq!(tokens[1].0, Token::Number("4".to_string()));
        assert_eq!(tokens[2].0, Token::Semicolon);
    }

    #[test]
    fn test_tokenize_block() {
        let input = "server { listen 80; }";
        let tokens = tokenize(input).unwrap();
        assert_eq!(tokens.len(), 6);
        assert_eq!(tokens[0].0, Token::Identifier("server".to_string()));
        assert_eq!(tokens[1].0, Token::OpenBrace);
        assert_eq!(tokens[2].0, Token::Identifier("listen".to_string()));
        assert_eq!(tokens[3].0, Token::Number("80".to_string()));
        assert_eq!(tokens[4].0, Token::Semicolon);
        assert_eq!(tokens[5].0, Token::CloseBrace);
    }

    #[test]
    fn test_tokenize_quoted_string() {
        let input = r#"root "/var/www/html";"#;
        let tokens = tokenize(input).unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].0, Token::Identifier("root".to_string()));
        assert_eq!(tokens[1].0, Token::String("/var/www/html".to_string()));
    }

    #[test]
    fn test_tokenize_comment() {
        let input = "# this is a comment\nworker_processes 4;";
        let tokens = tokenize(input).unwrap();
        assert_eq!(tokens[0].0, Token::Comment(" this is a comment".to_string()));
    }
}
