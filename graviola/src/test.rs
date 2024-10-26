// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub(crate) trait CavpSink {
    fn on_meta(&mut self, meta: &str);
    fn on_value(&mut self, name: &str, value: Value<'_>);
}

#[derive(Debug)]
pub(crate) struct Value<'a>(&'a str);

impl Value<'_> {
    pub(crate) fn bytes(&self) -> Vec<u8> {
        if self.0.len() % 2 == 0 {
            (0..self.0.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&self.0[i..i + 2], 16).unwrap())
                .collect()
        } else {
            let mut buf = self.0.to_string();
            buf.insert(0, '0');
            (0..buf.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&buf[i..i + 2], 16).unwrap())
                .collect()
        }
    }

    pub(crate) fn int(&self) -> u64 {
        self.0.parse::<u64>().unwrap()
    }

    pub(crate) fn str(&self) -> &str {
        self.0
    }
}

pub(crate) fn process_cavp(filename: impl AsRef<Path>, sink: &mut dyn CavpSink) {
    let f = File::open(filename).expect("cannot open {filename}");
    for line in BufReader::new(f).lines() {
        let line = line.unwrap();

        match line.chars().next() {
            Some('[') => {
                let right = line.rfind(']').expect("missing ] for meta");
                sink.on_meta(&line[1..right]);
                continue;
            }
            Some('#') => {
                println!("{line}");
                continue;
            }
            None => continue,
            _ => {}
        };

        if let Some(equal_idx) = line.find(" = ") {
            let name = &line[..equal_idx];
            let value = &line[equal_idx + 3..];

            sink.on_value(name, Value(value));
        } else {
            sink.on_value(&line, Value(""));
        }
    }
}
