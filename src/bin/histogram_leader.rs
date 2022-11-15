use dpf_codes::{
    FieldElm,
    collect,
    config,
    dpf,
    fastfield,
    histogram_rpc::{
        HistogramAddKeysRequest,
        HistogramResetRequest,
        HistogramTreeInitRequest,
        HistogramTreeCrawlRequest,
        HistogramTreeCrawlLastRequest,
        HistogramComputeHashesRequest,
        HistogramAddLeavesBetweenClientsRequest,
    },
    HistogramCollectorClient,
};

use futures::try_join;
use itertools::Itertools;
use num_traits::cast::ToPrimitive;
use rand::{Rng, distributions::Alphanumeric,};
use rayon::prelude::*;
use std::{io, time::{Duration, SystemTime, Instant},};
use tarpc::{client, context, tokio_serde::formats::Json, serde_transport::tcp,};

type Key = dpf::DPFKey<fastfield::FE,FieldElm>;

fn long_context() -> context::Context {
    let mut ctx = context::current();

    // Increase timeout to one hour
    ctx.deadline = SystemTime::now() + Duration::from_secs(1000000);
    ctx
}


fn sample_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric) as char)
        .take(len / 8)
        .collect()
}

fn generate_keys(cfg: &config::Config) -> Vec<(Vec<Key>, Vec<Key>)> {
    println!("data_len = {} bits\n", cfg.data_len * 8);

    let ((keys20, keys02), ((keys01, keys10), (keys12, keys21))): 
        ((Vec<Key>, Vec<Key>), ((Vec<Key>, Vec<Key>), (Vec<Key>, Vec<Key>))) = 
    rayon::iter::repeat(0)
    .take(cfg.unique_buckets)
    .enumerate()
    .map(|(_i, _)| {
        let data_string = sample_string(cfg.data_len * 8);
        // let bit_str = dpf_codes::bits_to_bitstring(
        //     dpf_codes::string_to_bits(&data_string).as_slice()
        // );
        // println!("Client({}) \t input \"{}\" ({})", _i, data_string, bit_str);
        
        (
            dpf::DPFKey::gen_from_str(&data_string),
            (dpf::DPFKey::gen_from_str(&data_string), 
            dpf::DPFKey::gen_from_str(&data_string))
        )
    })
    .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys01[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    vec![(keys01, keys10), (keys12, keys21), (keys20, keys02)]
}

async fn reset_servers(
    clients: &mut Vec<Client>,
) -> io::Result<()> {
    for client in clients.iter() {
        let response_0 = client.0.reset(
            long_context(), HistogramResetRequest { client_idx: 0 }
        );
        let response_1 = client.1.reset(
            long_context(), HistogramResetRequest { client_idx: 1 }
        );
        try_join!(response_0, response_1).unwrap();
    }

    let response_0 = clients[0].0.reset(
        long_context(), HistogramResetRequest { client_idx: 2 }
    );
    let response_1 = clients[0].1.reset(
        long_context(), HistogramResetRequest { client_idx: 2 }
    );
    try_join!(response_0, response_1).unwrap();

    Ok(())
}

async fn tree_init(
    clients: &mut Vec<Client>,
) -> io::Result<()> {
    for client in clients.iter() {
        let response_0 = client.0.tree_init(
            long_context(), HistogramTreeInitRequest { client_idx: 0 }
        );
        let response_1 = client.1.tree_init(
            long_context(), HistogramTreeInitRequest { client_idx: 1 }
        );
        try_join!(response_0, response_1).unwrap();
    }

    let response_0 = clients[0].0.tree_init(
        long_context(), HistogramTreeInitRequest { client_idx: 2 }
    );
    let response_1 = clients[0].1.tree_init(
        long_context(), HistogramTreeInitRequest { client_idx: 2 }
    );
    try_join!(response_0, response_1).unwrap();

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    clients: &Vec<Client>,
    keys: &Vec<(Vec<dpf::DPFKey<fastfield::FE,FieldElm>>, Vec<dpf::DPFKey<fastfield::FE,FieldElm>>)>,
    nreqs: usize,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkeys_0 = vec![Vec::with_capacity(nreqs); 3];
    let mut addkeys_1 = vec![Vec::with_capacity(nreqs); 3];
    for _ in 0..nreqs {
        let idx = zipf.sample(&mut rng) - 1;
        for i in 0..3 {
            addkeys_0[i].push(keys[i].0[idx].clone());
            addkeys_1[i].push(keys[i].1[idx].clone());
        }
    }

    for i in 0..clients.len() {
        let response_0 = clients[i].0.add_keys(
            long_context(),
            HistogramAddKeysRequest { client_idx: 0, keys: addkeys_0[i].clone() }
        );
        let response_1 = clients[i].1.add_keys(
            long_context(),
            HistogramAddKeysRequest { client_idx: 1, keys: addkeys_1[i].clone() }
        );
        try_join!(response_0, response_1).unwrap();
    }

    let response_0 = clients[0].0.add_keys(
        long_context(),
        HistogramAddKeysRequest { client_idx: 2, keys: addkeys_0[2].clone() }
    );
    let response_1 = clients[0].1.add_keys(
        long_context(),
        HistogramAddKeysRequest { client_idx: 2, keys: addkeys_1[2].clone() }
    );
    try_join!(response_0, response_1).unwrap();

    Ok(())
}

async fn run_level(
    clients: &mut Vec<Client>,
    _level: usize,
    _start_time: Instant,
) -> io::Result<()> {
    // Tree crawl
    // println!(
    //     "TreeCrawlStart {:?} - {:?}", _level, _start_time.elapsed().as_secs_f64()
    // );
    for client in clients.iter() {
        let response_0 = client.0.histogram_tree_crawl(
            long_context(), HistogramTreeCrawlRequest { client_idx: 0 }
        );
        let response_1 = client.1.histogram_tree_crawl(
            long_context(), HistogramTreeCrawlRequest { client_idx: 1 }
        );
        let (vals_0, vals_1) = try_join!(response_0, response_1).unwrap();
        assert_eq!(vals_0.len(), vals_1.len());
    }
    
    let response_0 = clients[0].0.histogram_tree_crawl(
        long_context(), HistogramTreeCrawlRequest { client_idx: 2 }
    );
    let response_1 = clients[0].1.histogram_tree_crawl(
        long_context(), HistogramTreeCrawlRequest { client_idx: 2 }
    );
    let (_, _) = try_join!(response_0, response_1).unwrap();

    // println!(
    //     "TreeCrawlDone {:?} - {:?}", _level, _start_time.elapsed().as_secs_f64()
    // );

    Ok(())
}

fn check_hashes(
    verified: &mut Vec<bool>,
    hashes_0: &Vec<Vec<u8>>,
    hashes_1: &Vec<Vec<u8>>
) {
    // Check hashes
    for ((i, h0), h1) in hashes_0.iter().enumerate().zip_eq(hashes_1) {
        if h0.len() != h0.iter().zip_eq(h1.iter()).filter(|&(h0, h1)| h0 == h1).count() {
            println!("Client({}) {} != {}", i, hex::encode(h0), hex::encode(h1));
            verified[i] = false;
        }
    }
}

fn check_taus(
    verified: &mut Vec<bool>,
    tau_vals_0: &Vec<FieldElm>,
    tau_vals_1: &Vec<FieldElm>,
) {
    // Check taus
    for ((i, t0), t1) in tau_vals_0.iter().enumerate().zip_eq(tau_vals_1) {
        if t0.value() != t1.value() {
            println!("Client({}) {} != {}", i, 
                t0.value().to_u32().unwrap(), 
                t1.value().to_u32().unwrap()
            );
            verified[i] = false;
        }
    }
}

fn check_hashes_and_taus(
    verified: &mut Vec<bool>,
    hashes_0: &Vec<Vec<u8>>,
    hashes_1: &Vec<Vec<u8>>,
    tau_vals: &Vec<FieldElm>,
) {
    // Check hashes and taus
    for ((i, h0), h1) in hashes_0.iter().enumerate().zip_eq(hashes_1) {
        if h0.len() != h0.iter().zip_eq(h1.iter()).filter(|&(h0, h1)| h0 == h1).count()
            || tau_vals[i].value().to_u32().unwrap() != 1 
        {
            println!("Client({}) h0: {}, h1: {}, tau: {}", 
                i, hex::encode(h0), hex::encode(h1),
                tau_vals[i].value().to_u32().unwrap()
            );
            verified[i] = false;
        }
    }
}

async fn run_level_last(
    clients: &mut Vec<Client>,
    _start_time: Instant,
) -> io::Result<()> {
    // Tree crawl
    // println!("TreeCrawlStart last {:?}", _start_time.elapsed().as_secs_f64());
    let response_00 = clients[0].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 0 }
    );
    let response_01 = clients[0].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 1 }
    );
    let ((hashes_00, tau_vals_00), (hashes_01, tau_vals_01)) = 
        try_join!(response_00, response_01).unwrap();
    assert_eq!(hashes_00.len(), hashes_01.len());
    let response_11 = clients[1].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 0 }
    );
    let response_12 = clients[1].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 1 }
    );
    let ((hashes_11, tau_vals_11), (hashes_12, tau_vals_12)) = 
        try_join!(response_11, response_12).unwrap();
    assert_eq!(hashes_11.len(), hashes_12.len());
        
    let response_22 = clients[2].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 0 }
    );
    let response_20 = clients[2].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 1 }
    );
    let ((hashes_22, tau_vals_22), (hashes_20, tau_vals_20)) = 
        try_join!(response_22, response_20).unwrap();
    assert_eq!(hashes_11.len(), hashes_12.len());

    let response_020 = clients[0].0.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 2 }
    );
    let response_021 = clients[0].1.histogram_tree_crawl_last(
        long_context(), HistogramTreeCrawlLastRequest { client_idx: 2 }
    );
    let ((hashes_020, tau_vals_020), (hashes_021, tau_vals_021)) = 
        try_join!(response_020, response_021).unwrap();

    let mut ver_0 = vec![true; hashes_00.len()];
    let mut ver_1 = vec![true; hashes_11.len()];
    let mut ver_2 = vec![true; hashes_22.len()];

    // Check that \tau_2,0 and \pi_2,0 from S0 and S2 are the same
    check_hashes(&mut ver_0, &hashes_020, &hashes_22);
    check_taus(&mut ver_0, &tau_vals_020, &tau_vals_22);
    // Check that \tau_2,1 and \pi_2,1 from S0 and S2 are the same
    check_hashes(&mut ver_1, &hashes_021, &hashes_20);
    check_taus(&mut ver_1, &tau_vals_021, &tau_vals_20);

    // println!("TreeCrawlDone last - {:?}", _start_time.elapsed().as_secs_f64());

    let tau_vals_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_00, &tau_vals_01
    );
    let tau_vals_1 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_11, &tau_vals_12
    );
    let tau_vals_2 = &collect::KeyCollection::<fastfield::FE, FieldElm>::reconstruct_shares(
        &tau_vals_22, &tau_vals_20
    );

    // Check s0, s1 hashes and taus
    check_hashes_and_taus(&mut ver_0, &hashes_00, &hashes_01, &tau_vals_0);
    // Check s1, s2 hashes and taus
    check_hashes_and_taus(&mut ver_1, &hashes_11, &hashes_12, &tau_vals_1);
    // Check s2, s0 hashes and taus
    check_hashes_and_taus(&mut ver_2, &hashes_22, &hashes_20, &tau_vals_2);
    assert_eq!(
        ver_0.iter()
            .zip_eq(ver_1.iter()).zip_eq(ver_2.iter())
            .filter(|&((v0, v1), v2)| v0 == v1 && v1 == v2).count(),
        ver_0.len()
    );

    let resp_0 = clients[0].0.histogram_compute_hashes(
        long_context(), HistogramComputeHashesRequest { client_idx: 0 }
    );
    let resp_1 = clients[0].1.histogram_compute_hashes(
        long_context(), HistogramComputeHashesRequest { client_idx: 1 }
    );
    let (hashes_0, hashes_1) = try_join!(resp_0, resp_1).unwrap();
    check_hashes(&mut ver_0, &hashes_0, &hashes_1);

    let response_00 = clients[0].0.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 0, verified: ver_0.clone() }
    );
    let response_01 = clients[0].1.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 1, verified: ver_0.clone() }
    );
    let (shares_00, shares_01) = try_join!(response_00, response_01).unwrap();

    let response_11 = clients[1].0.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 0, verified: ver_1.clone() }
    );
    let response_12 = clients[1].1.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 1, verified: ver_1 }
    );
    let (shares_11, shares_12) = try_join!(response_11, response_12).unwrap();
    
    let response_22 = clients[2].0.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 0, verified: ver_2.clone() }
    );
    let response_20 = clients[2].1.histogram_add_leaves_between_clients(
        long_context(),
        HistogramAddLeavesBetweenClientsRequest { client_idx: 1, verified: ver_2 }
    );
    let (shares_22, shares_20) = try_join!(response_22, response_20).unwrap();

    let hist_0 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_00, &shares_01
    );
    let hist_1 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_11, &shares_12
    );
    let hist_2 = &collect::KeyCollection::<fastfield::FE, FieldElm>::final_values(
        &shares_22, &shares_20
    );

    for ((res_0, res_1), res_2) in hist_0.iter().zip_eq(hist_1).zip_eq(hist_2) {
        assert_eq!(res_0.value.value(), res_1.value.value());
        assert_eq!(res_0.value.value(), res_2.value.value());
        let bits = dpf_codes::bits_to_bitstring(&res_0.path);
        if res_0.value.value().to_u32().unwrap() > 0 {
            println!("Value ({}) \t Count: {:?}", bits, res_0.value.value());
        }
    }
    Ok(())
}

// Client/Server Pairs: 
// Client 0 connects to S0 and S1
// Client 1 connects to S1 and S2
// Client 2 connects to S2 and S0

type Client = (HistogramCollectorClient, HistogramCollectorClient);

#[tokio::main]
async fn main() -> io::Result<()> {
    //println!("Using only one thread!");
    //rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();

    env_logger::init();
    let (cfg, _, nreqs) = config::get_args("Leader", false, true);

    let client_0: Client = (
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_0, Json::default).await?
        ).spawn(),
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_1, Json::default).await?
        ).spawn()
    );
    let client_1: Client = (
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_1, Json::default).await?
        ).spawn(),
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_2, Json::default).await?
        ).spawn()
    );
    let client_2: Client = (
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_2, Json::default).await?
        ).spawn(), 
        HistogramCollectorClient::new(
            client::Config::default(),
            tcp::connect(cfg.server_0, Json::default).await?
        ).spawn()
    );
    let mut clients = vec![client_0, client_1, client_2];

    let start = Instant::now();
    // let (keys0, keys1) = generate_keys(&cfg);
    let keys = generate_keys(&cfg);
    
    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys[0].0.len(), delta, delta / (keys[0].0.len() as f64)
    );

    reset_servers(&mut clients).await?;

    let mut left_to_go = nreqs;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut resps = vec![];

        for _j in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.addkey_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                resps.push(add_keys(
                    &cfg,
                    &clients,
                    &keys,
                    this_batch,
                ));
            }
        }

        for r in resps {
            r.await?;
        }
    }

    tree_init(&mut clients).await?;

    let start = Instant::now();
    let bitlen = cfg.data_len * 8; // bits
    for level in 0..bitlen-1 {
        run_level(&mut clients, level, start).await?;
        // println!("Level {:?}: {:?}", level, start.elapsed().as_secs_f64());
    }

    run_level_last(&mut clients, start).await?;
    println!("Level {:?}: {:?}", bitlen, start.elapsed().as_secs_f64());

    Ok(())
}
