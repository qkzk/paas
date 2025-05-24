## ALPHA VERSION 

This is an alpha version which is still in development.

# PaaS - Pandoc As A Service

Have you ever wished to creates a pdf from some markdown ? There's not a lot of solutions online and your data may be used by the provider...

PAAS is a self hosting solution allowing you to execute pandoc from your server with all the filters you may have installed. 
Log in on your server, paste some markdow and your pdf is created and downloaded immediatly.

---

This is a minimal web server written in Rust using [Axum](https://docs.rs/axum/latest/axum/), designed for simple login-protected pandoc conversion.

It provides:

- Execution on server side [pandoc](https://pandoc.org/) from anywhere
- A basic HTML login page
- Password-based authentication
- Secure cookie-based session management

## Server usage 

You can run the development version with debug symbols:

```bash
export RUST_BACKTRACE=1
cargo build
sudo PAAS_PASSWORD=super 
FULLCHAIN=/path/to/fullchain.pem 
PRIVATEKEY=/path/to/privkey.pem
PORT=3000
./target/debug/paas
````

To run the release version (optimized):

```bash
cargo build --release
sudo PAAS_PASSWORD=super 
FULLCHAIN=/path/to/fullchain.pem 
PRIVATEKEY=/path/to/privkey.pem
PORT=3000
./target/release/paas
```

Replace `super` with your desired password.

**Note:** `sudo` is required because the server uses HTTPS on port 3000.

### Configuration 

All configuration is made through environement variables :

- port 
- password 
- cert fullchain path 
- cert private key path 

## Client Usage 

1. Join your server at `your.domain:3000/login`,
2. Input the password provided when launching the server,
3. Type some markdown (only), pass some arguments to pandoc and a desired filename
4. Voilà ! Pandoc does the conversion like if you were at home.

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** license.
