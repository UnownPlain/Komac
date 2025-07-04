use std::collections::HashMap;

use serde::Deserialize;
use tracing::warn;

#[derive(Debug, Deserialize)]
#[serde(from = "&str")]
pub struct InstallCondition(Expr);

#[derive(Debug, Clone)]
pub enum Value {
    Bool(bool),
    Int(u32),
}

impl InstallCondition {
    pub fn new(input: &str) -> Self {
        Self(Parser::new(tokenize(input)).parse_expr())
    }

    pub fn evaluate(&self, variables: &HashMap<&str, Value>) -> bool {
        self.inner().eval(variables)
    }

    #[inline]
    const fn inner(&self) -> &Expr {
        &self.0
    }
}

impl From<&str> for InstallCondition {
    #[inline]
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    #[inline]
    const fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn parse_expr(&mut self) -> Expr {
        self.parse_or()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    const fn advance(&mut self) {
        self.pos += 1;
    }

    fn expect(&mut self, expected: &Token) {
        if self.peek() == Some(expected) {
            self.advance();
        } else {
            panic!("Expected {expected:?}, got {:?}", self.peek());
        }
    }

    fn parse_or(&mut self) -> Expr {
        let mut expr = self.parse_and();
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let rhs = self.parse_and();
            expr = Expr::Or(Box::new(expr), Box::new(rhs));
        }
        expr
    }

    fn parse_and(&mut self) -> Expr {
        let mut expr = self.parse_not();
        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let rhs = self.parse_not();
            expr = Expr::And(Box::new(expr), Box::new(rhs));
        }
        expr
    }

    fn parse_not(&mut self) -> Expr {
        if matches!(self.peek(), Some(Token::Not)) {
            self.advance();
            let expr = self.parse_primary();
            Expr::Not(Box::new(expr))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Expr {
        match self.peek() {
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_expr();
                self.expect(&Token::RParen);
                expr
            }
            Some(Token::Ident(name)) => {
                let name = name.clone();
                self.advance();
                if matches!(self.peek(), Some(Token::Eq)) {
                    self.advance();
                    if let Some(Token::Number(num)) = self.peek() {
                        let num = *num;
                        self.advance();
                        Expr::Eq(name, num)
                    } else {
                        panic!("Expected number after '='");
                    }
                } else {
                    Expr::Var(name)
                }
            }
            other => panic!("Unexpected token: {:?}", other),
        }
    }
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&char) = chars.peek() {
        match char {
            char if char.is_whitespace() => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            '=' => {
                tokens.push(Token::Eq);
                chars.next();
            }
            '0'..='9' => {
                let mut value = 0;
                while let Some(digit) = chars.peek().and_then(|char| char.to_digit(10)) {
                    value = value * 10 + digit;
                    chars.next();
                }
                tokens.push(Token::Number(value));
            }
            _ => {
                let mut ident = String::new();
                while let Some(&char) = chars
                    .peek()
                    .filter(|char| !char.is_whitespace() && !['(', ')', '='].contains(char))
                {
                    ident.push(char);
                    chars.next();
                }
                tokens.push(match ident.as_str() {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "NOT" => Token::Not,
                    _ => Token::Ident(ident),
                });
            }
        }
    }

    tokens
}

#[derive(Debug)]
pub enum Expr {
    Var(String),
    Eq(String, u32),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    pub fn eval(&self, variables: &HashMap<&str, Value>) -> bool {
        match self {
            Self::Var(name) => match variables.get(name.as_str()) {
                Some(Value::Bool(bool)) => *bool,
                Some(Value::Int(int)) => *int != 0,
                None => {
                    warn!("Variable `{name}` not found in Burn variables");
                    true
                }
            },
            Self::Eq(name, val) => match variables.get(name.as_str()) {
                Some(Value::Int(int)) => *int == *val,
                Some(Value::Bool(bool)) => (*val == 1) == *bool,
                None => {
                    warn!("Variable `{name}` not found in Burn variables");
                    true
                }
            },
            Self::Not(inner) => !inner.eval(variables),
            Self::And(lhs, rhs) => lhs.eval(variables) && rhs.eval(variables),
            Self::Or(lhs, rhs) => lhs.eval(variables) || rhs.eval(variables),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Eq,
    Ident(String),
    Number(u32),
}
