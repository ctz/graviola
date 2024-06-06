use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "asm.pest"]
pub struct CSVParser;

fn main() {
    match CSVParser::parse(Rule::File, include_str!("../p256_montjadd.S")) {
        Err(err) => 
        { panic!("parse error: {}", err); }
        Ok(result) => { panic!("parse ok {}", result); }
    };
}
