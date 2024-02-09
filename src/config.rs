use clap::{App, Arg};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub data_bytes: usize,
    pub addkey_batch_size: usize,
    pub hashes_batch_size: usize,
    pub unique_buckets: usize,
    pub threshold: f64,
    pub zipf_exponent: f64,
    pub server_0: String,
    pub server_1: String,
    pub server_2: String,
}

pub fn get_config(filename: &str) -> Config {
    let json_data = &fs::read_to_string(filename).expect("Cannot open JSON file");
    serde_json::from_str(json_data).expect("Cannot parse JSON config")
}

pub fn get_args(
    name: &str,
    get_server_id: bool,
    get_n_reqs: bool,
    get_malicious: bool,
) -> (Config, i8, usize, f32) {
    let mut flags = App::new(name)
        .version("0.1")
        .about("Privacy-preserving heavy-hitters for location data.")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILENAME")
                .help("Location of JSON config file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server0")
                .short("s0")
                .long("server-0")
                .value_name("STRING")
                .help("Server 0 host path to connect to, ex: 0.0.0.0:8000")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server1")
                .short("s0")
                .long("server-1")
                .value_name("STRING")
                .help("Server 1 host path to connect to, ex: 0.0.0.0:8001")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server2")
                .short("s0")
                .long("server-2")
                .value_name("STRING")
                .help("Server 2 host path to connect to, ex: 0.0.0.0:8002")
                .required(false)
                .takes_value(true),
        );
    if get_server_id {
        flags = flags.arg(
            Arg::with_name("server_id")
                .short("i")
                .long("server_id")
                .value_name("NUMBER")
                .help("Zero-indexed ID of server")
                .required(true)
                .takes_value(true),
        );
    }
    if get_n_reqs {
        flags = flags.arg(
            Arg::with_name("num_requests")
                .short("n")
                .long("num_requests")
                .value_name("NUMBER")
                .help("Number of client requests to generate")
                .required(true)
                .takes_value(true),
        );
    }
    if get_malicious {
        flags = flags.arg(
            Arg::with_name("malicious")
                .short("m")
                .long("malicious")
                .value_name("NUMBER")
                .help("Percentage of malicious clients")
                .required(false)
                .takes_value(true),
        );
    }
    let flags = flags.get_matches();
    let mut config = get_config(flags.value_of("config").unwrap());

    let mut server_id = -1;
    if get_server_id {
        server_id = flags.value_of("server_id").unwrap().parse().unwrap();
    } else {
        // If it's the leader.
        if flags.is_present("server0") {
            config.server_0 = flags.value_of("server0").unwrap().parse().unwrap();
        }
        if flags.is_present("server1") {
            config.server_1 = flags.value_of("server1").unwrap().parse().unwrap();
        }
        if flags.is_present("server2") {
            config.server_2 = flags.value_of("server2").unwrap().parse().unwrap();
        }
    }

    let mut n_reqs = 0;
    if get_n_reqs {
        n_reqs = flags.value_of("num_requests").unwrap().parse().unwrap();
    }

    let mut malicious = 0.0;
    if flags.is_present("malicious") {
        malicious = flags.value_of("malicious").unwrap().parse::<f32>().unwrap();
    }

    (config, server_id, n_reqs, malicious)
}
