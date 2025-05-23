# PaaS - Pandoc As A Service

This is a minimal web server written in Rust using [Axum](https://docs.rs/axum/latest/axum/), designed for simple login-protected pandoc conversion.

It provides:

- Execution on server side [pandoc](https://pandoc.org/) from anywhere
- A basic HTML login page
- Password-based authentication
- Secure cookie-based session management
- Redirect after login

## Usage

You can run the development version with debug symbols:

```bash
export RUST_BACKTRACE=1
cargo build
sudo PAAS_PASSWORD=super ./target/debug/paas
````

To run the release version (optimized):

```bash
cargo build --release
sudo PAAS_PASSWORD=super ./target/release/paas
```

Replace `super` with your desired password.

**Note:** `sudo` is required because the server uses HTTPS on port 3000.

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** license.

You are free to:

* Share — copy and redistribute the material in any medium or format
* Adapt — remix, transform, and build upon the material

**Under the following terms:**

* **Attribution** — You must give appropriate credit.
* **NonCommercial** — You may not use the material for commercial purposes.

For the full license text, see: [https://creativecommons.org/licenses/by-nc/4.0/](https://creativecommons.org/licenses/by-nc/4.0/)

