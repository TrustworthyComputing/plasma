<h1 align="center">PLASMA: Private, Lightweight Aggregated Statistics against Malicious Adversaries <a href="https://github.com/TrustworthyComputing/plasma/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a> </h1>


### WARNING: This is not production-ready code.
This is software for a research prototype. Please do *NOT* use this code in production.
This repository builds upon [heavy-hitters](https://github.com/henrycg/heavyhitters).


### How to cite this work
PLASMA will appear in [PoPETS 2024](https://petsymposium.org/popets/2024/) (the preprint can be accessed [here](https://eprint.iacr.org/2023/080)).
You can cite this work as follows:
```bibtex
@Article{PoPETS:MouSarTso24,
  author =       "Dimitris Mouris and
                  Pratik Sarkar and
                  Nektarios Georgios Tsoutsos",
  title =        "{PLASMA: Private, Lightweight Aggregated Statistics against Malicious Adversaries}",
  year =         2024,
  volume =       2024,
  month =        July,
  journal =      "{Proceedings on Privacy Enhancing Technologies}",
  number =       3,
  pages =        "1--19",
}
```

## Build & Run With Docker Compose
The following runs three servers and the leader each in a different container:
```bash
❯❯ docker compose up
```

## Getting started
First, make sure that you have a working Rust installation:

```bash
❯❯ rustc --version
rustc 1.67.1
❯❯ cargo --version
cargo 1.67.1
```
Note that we don't require the exact Rust version, but this is the one we used in our experiments.

### Build from sources
```bash
cargo build --release
```

Run the tests:
```bash
cargo test --release
```

## Heavy Hitters
First off, run the servers in different shells.

Server 0:
```bash
cargo run --release --bin server -- --config src/bin/config_8.json --server_id 0
```

Server 1:
```bash
cargo run --release --bin server -- --config src/bin/config_8.json --server_id 1
```

Server 2:
```bash
cargo run --release --bin server -- --config src/bin/config_8.json --server_id 2
```

Now, the servers should be ready to process client requests. In a forth shell, run the following command to send 100 client requests to the servers:

Clients:
```bash
cargo run --release --bin leader -- --config src/bin/config_8.json -n 100
```

To run with the presence of malicious clients include the `--malicious` flag followed by the percentage of malicious clients to generate ([0.0, 0.9]). For instance, to run with 5% malicious clients use:
```bash
cargo run --release --bin leader -- --config src/bin/config_8.json -n 100 --malicious 0.05
```


## The config file
The client and servers use a common configuration file, which contains the parameters for the system. An example of one such file is in `src/bin/config_8.json`. The contents of that file are here:

```bash
{
  "data_bytes": 1,
  "threshold": 0.01,
  "server_0": "0.0.0.0:8000",
  "server_1": "0.0.0.0:8001",
  "server_2": "0.0.0.0:8002",
  "addkey_batch_size": 1000,
  "hashes_batch_size": 100000,
  "unique_buckets": 1000,
  "zipf_exponent": 1.03
}
```

The parameters are:

* `data_bytes`: Number of bytes of each string (x8 for bits).
* `threshold`: The servers will output the collection of strings that more than a `threshold` of clients hold.
* `server0`, `server1`, and `server2`: The `IP:port` of tuple for the two servers. The servers can run on different IP addresses, but these IPs must be publicly addressable.
* `addkey_batch_size`: The number of each type of RPC request to bundle together. The underlying RPC library has an annoying limit on the size of each RPC request, so you cannot set these values too large.
* `unique_buckets` and `zipf_exponent`: Each simulated client samples its private string from a Zipf distribution over strings with parameter `zipf_exponent` and support `unique_buckets`.

## Acknowledgments
This work was supported by the National Science Foundation (Awards #2239334 #1931714, #1414119) and the DARPA SIEVE program.

<p align="center">
    <img src="./logos/twc.png" height="20%" width="20%">
</p>
<h4 align="center">Trustworthy Computing Group</h4>
