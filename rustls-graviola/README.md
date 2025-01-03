<h1 align="center">rustls-graviola</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/ctz/graviola/main/admin/picture.png">

[![Latest release](https://img.shields.io/crates/v/rustls-graviola)](https://crates.io/crates/rustls-graviola)
[![Documentation](https://img.shields.io/docsrs/rustls-graviola)](https://docs.rs/rustls-graviola/)

This crate provides an integration between [rustls](https://github.com/rustls/rustls) and [Graviola](https://github.com/ctz/graviola/).

Use it like:

```rust
rustls_graviola::default_provider()
    .install_default()
    .unwrap();
```

And then use rustls as normal.

License: Apache-2.0 OR ISC OR MIT-0
