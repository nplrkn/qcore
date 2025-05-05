See https://rust-lang.github.io/rust-bindgen/command-line-usage.html.

# Setup
```
cargo install bindgen
sudo apt-get install -y clang
```
# Generate
```
bindgen includes.h -o sctp_bindings.rs
```
Then copy sctp_bindings.rs into the src directory.