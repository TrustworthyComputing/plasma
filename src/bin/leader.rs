use plasma::{
    collect, config, dpf,
    rpc::{
        AddKeysRequest, FinalSharesRequest, GetMerkleRootsRequest, GetProofsRequest, ResetRequest,
        TreeCrawlLastRequest, TreeCrawlRequest, TreeInitRequest, TreePruneRequest,
    },
    HHCollectorClient,
};

use futures::future::join_all;
use rand::{distributions::Alphanumeric, Rng};
use rayon::prelude::*;
use std::{
    io,
    time::{Duration, Instant, SystemTime},
};
use tarpc::{client, context, serde_transport::tcp, tokio_serde::formats::Bincode};

type Key = dpf::DPFKey<u64>;
type Client = HHCollectorClient;

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

// fn sample_location() -> (f64, f64) {
//     let mut rng = rand::thread_rng();
//     (rng.gen_range(-180.0..180.0) as f64, rng.gen_range(-90.0..90.0) as f64)
// }

fn generate_keys(cfg: &config::Config) -> Vec<(Vec<Key>, Vec<Key>)> {
    let ((keys20, keys02), ((keys01, keys10), (keys12, keys21))): (
        (Vec<Key>, Vec<Key>),
        ((Vec<Key>, Vec<Key>), (Vec<Key>, Vec<Key>)),
    ) = rayon::iter::repeat(0)
        .take(cfg.unique_buckets)
        .enumerate()
        .map(|(_i, _)| {
            let data_string = sample_string(cfg.data_bytes * 8);
            // let bit_str = plasma::bits_to_bitstring(
            //     plasma::string_to_bits(&data_string).as_slice()
            // );
            // println!("Client({}) \t input \"{}\" ({})", _i, data_string, bit_str);
            // let loc = sample_location();
            // let data_string = encode(Point::new(loc.0, loc.1), cfg.data_bytes * 8);
            (
                dpf::DPFKey::gen_from_str(&data_string),
                (
                    dpf::DPFKey::gen_from_str(&data_string),
                    dpf::DPFKey::gen_from_str(&data_string),
                ),
            )
        })
        .unzip();

    let encoded: Vec<u8> = bincode::serialize(&keys01[0]).unwrap();
    println!("Key size: {:?} bytes", encoded.len());

    vec![(keys01, keys10), (keys12, keys21), (keys20, keys02)]
}

async fn reset_servers(clients: &[&Client]) -> io::Result<()> {
    let responses = vec![
        // Session 0
        clients[0].reset(long_context(), ResetRequest { client_idx: 0 }),
        clients[1].reset(long_context(), ResetRequest { client_idx: 1 }),
        // Session 1
        clients[1].reset(long_context(), ResetRequest { client_idx: 0 }),
        clients[2].reset(long_context(), ResetRequest { client_idx: 1 }),
        // Session 2
        clients[2].reset(long_context(), ResetRequest { client_idx: 0 }),
        clients[0].reset(long_context(), ResetRequest { client_idx: 2 }),
        // Extra
        clients[0].reset(long_context(), ResetRequest { client_idx: 1 }),
        clients[1].reset(long_context(), ResetRequest { client_idx: 2 }),
    ];

    join_all(responses).await;

    Ok(())
}

async fn tree_init(clients: &[&Client]) -> io::Result<()> {
    let mut responses = vec![];

    // Session 0
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 0 })
            .await
    }));
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 1 })
            .await
    }));

    // Session 1
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 0 })
            .await
    }));
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 1 })
            .await
    }));

    // Session 2
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 0 })
            .await
    }));
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 2 })
            .await
    }));

    // extra
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 1 })
            .await
    }));
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move {
        cl.tree_init(long_context(), TreeInitRequest { client_idx: 2 })
            .await
    }));

    join_all(responses).await;

    Ok(())
}

async fn add_keys(
    cfg: &config::Config,
    clients: &[&Client],
    keys: &[(Vec<dpf::DPFKey<u64>>, Vec<dpf::DPFKey<u64>>)],
    num_clients: usize,
    malicious_percentage: f32,
) -> io::Result<()> {
    use rand::distributions::Distribution;
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(cfg.unique_buckets, cfg.zipf_exponent).unwrap();

    let mut addkeys_0 = vec![Vec::with_capacity(num_clients); 3];
    let mut addkeys_1 = vec![Vec::with_capacity(num_clients); 3];
    for r in 0..num_clients {
        let idx_1 = zipf.sample(&mut rng) - 1;
        let mut idx_2 = idx_1;
        if rand::thread_rng().gen_range(0.0..1.0) < malicious_percentage {
            idx_2 += 1;
            println!("Malicious {}", r);
        }
        for i in 0..3 {
            addkeys_0[i].push(keys[i].0[idx_1].clone());
            addkeys_1[i].push(keys[i].1[idx_2 % cfg.unique_buckets].clone());
        }
    }

    let mut responses = vec![];
    // Session 0
    let keys = addkeys_0[0].clone();
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 0,
                keys,
            },
        )
        .await
    }));
    let keys = addkeys_1[0].clone();
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 1,
                keys,
            },
        )
        .await
    }));

    // Session 1
    let keys = addkeys_0[1].clone();
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 0,
                keys,
            },
        )
        .await
    }));
    let keys = addkeys_1[1].clone();
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 1,
                keys,
            },
        )
        .await
    }));

    // Session 2
    let keys = addkeys_0[2].clone();
    let cl = clients[2].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 0,
                keys,
            },
        )
        .await
    }));
    let keys = addkeys_1[2].clone();
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 2,
                keys,
            },
        )
        .await
    }));

    // extra
    let keys = addkeys_1[1].clone();
    let cl = clients[0].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 1,
                keys,
            },
        )
        .await
    }));
    let keys = addkeys_0[2].clone();
    let cl = clients[1].clone();
    responses.push(tokio::spawn(async move {
        cl.add_keys(
            long_context(),
            AddKeysRequest {
                client_idx: 2,
                keys,
            },
        )
        .await
    }));

    join_all(responses).await;

    Ok(())
}

async fn run_level(
    cfg: &config::Config,
    clients: &[&Client],
    num_clients: usize,
) -> io::Result<()> {
    let threshold = core::cmp::max(1, (cfg.threshold * (num_clients as f64)) as u64);
    let keep;
    let mut split_by = 1usize;
    let mut malicious = Vec::<usize>::new();
    let mut is_last = false;
    loop {
        let mut responses = vec![];

        // Session 0
        let cl = clients[0].clone();
        let ml = malicious.clone();
        responses.push(tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 0,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        }));
        let cl = clients[1].clone();
        let ml = malicious.clone();
        responses.push(tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 1,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        }));

        // Session 1
        let cl = clients[1].clone();
        let ml = malicious.clone();
        responses.push(tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 0,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        }));
        let cl = clients[2].clone();
        let ml = malicious.clone();
        responses.push(tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 1,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        }));

        // Session 2
        let cl = clients[2].clone();
        let ml = malicious.clone();
        let response_00 = tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 0,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        });
        let cl = clients[0].clone();
        let ml = malicious.clone();
        let response_01 = tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 2,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        });

        // extra
        let cl = clients[0].clone();
        let ml = malicious.clone();
        responses.push(tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 1,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        }));
        let cl = clients[1].clone();
        let ml = malicious.clone();
        responses.push(tokio::spawn(async move {
            cl.tree_crawl(
                long_context(),
                TreeCrawlRequest {
                    client_idx: 2,
                    split_by,
                    malicious: ml,
                    is_last,
                },
            )
            .await
        }));

        join_all(responses).await;

        let (counts_0, counts_1) = (response_00.await?.unwrap(), response_01.await?.unwrap());
        debug_assert_eq!(counts_0.len(), counts_1.len());

        malicious = Vec::new();
        let mut start = 0;
        while start < num_clients {
            let end = std::cmp::min(
                std::cmp::min(split_by, start + cfg.hashes_batch_size),
                num_clients,
            );

            let cl = clients[2].clone();
            let response_0 = tokio::spawn(async move {
                cl.get_merkle_roots(
                    long_context(),
                    GetMerkleRootsRequest {
                        client_idx: 0,
                        start,
                        end,
                    },
                )
                .await
            });
            let cl = clients[0].clone();
            let response_1 = tokio::spawn(async move {
                cl.get_merkle_roots(
                    long_context(),
                    GetMerkleRootsRequest {
                        client_idx: 2,
                        start,
                        end,
                    },
                )
                .await
            });

            let ((root_0, indices_0), (root_1, indices_1)) =
                (response_0.await?.unwrap(), response_1.await?.unwrap());

            if root_0.len() == 1 && root_0[0] == root_1[0] {
                break;
            }
            for i in 0..root_0.len() {
                if root_0[i] != root_1[i] {
                    debug_assert_eq!(indices_0[i], indices_1[i]);
                    malicious.push(indices_0[i]);
                }
            }
            start += cfg.hashes_batch_size;
        }

        if malicious.is_empty() || (split_by >= num_clients && is_last) {
            keep = collect::KeyCollection::<u64>::keep_values(&threshold, &counts_0, &counts_1);
            break;
        } else {
            // println!("Detected malicious {:?} out of {} clients", malicious, num_clients);
            if split_by >= num_clients {
                is_last = true;
            } else {
                split_by *= 2;
            }
        }
    }

    // Tree prune
    let mut responses = vec![];
    // Session 0
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 0,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 1,
                keep: k,
            },
        )
        .await
    }));

    // Session 1
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 0,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[2].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 1,
                keep: k,
            },
        )
        .await
    }));

    // Session 2
    let cl = clients[2].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 0,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 2,
                keep: k,
            },
        )
        .await
    }));

    // Extra
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 1,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 2,
                keep: k,
            },
        )
        .await
    }));

    join_all(responses).await;

    Ok(())
}

async fn run_level_last(
    cfg: &config::Config,
    clients: &[&Client],
    num_clients: usize,
) -> io::Result<()> {
    let start_last = Instant::now();
    let threshold = core::cmp::max(1, (cfg.threshold * (num_clients as f64)) as u64);

    // Session 0
    let cl = clients[0].clone();
    let response_00 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 0 })
            .await
    });
    let cl = clients[1].clone();
    let response_01 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 1 })
            .await
    });

    // Session 1
    let cl = clients[1].clone();
    let response_11 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 0 })
            .await
    });
    let cl = clients[2].clone();
    let response_12 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 1 })
            .await
    });

    // Session 2
    let cl = clients[2].clone();
    let response_22 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 0 })
            .await
    });
    let cl = clients[0].clone();
    let response_20 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 2 })
            .await
    });

    // extra
    let cl = clients[0].clone();
    let response_e0 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 1 })
            .await
    });
    let cl = clients[1].clone();
    let response_e1 = tokio::spawn(async move {
        cl.tree_crawl_last(long_context(), TreeCrawlLastRequest { client_idx: 2 })
            .await
    });

    let (cnt_values_00, cnt_values_01) = (response_00.await?.unwrap(), response_01.await?.unwrap());
    let (cnt_values_11, cnt_values_12) = (response_11.await?.unwrap(), response_12.await?.unwrap());
    let (cnt_values_22, cnt_values_20) = (response_22.await?.unwrap(), response_20.await?.unwrap());
    let (cnt_values_e0, cnt_values_e1) = (response_e0.await?.unwrap(), response_e1.await?.unwrap());

    debug_assert_eq!(cnt_values_00.len(), cnt_values_01.len());
    debug_assert_eq!(cnt_values_11.len(), cnt_values_12.len());
    debug_assert_eq!(cnt_values_22.len(), cnt_values_20.len());
    debug_assert_eq!(cnt_values_e0.len(), cnt_values_e1.len());

    // Receive counters in chunks to avoid having huge RPC messages.
    let mut start = 0;
    while start < num_clients {
        let end = std::cmp::min(num_clients, start + cfg.hashes_batch_size);

        // Session 0
        let cl = clients[0].clone();
        let response_00 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 0,
                    start,
                    end,
                },
            )
            .await
        });
        let cl = clients[1].clone();
        let response_01 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 1,
                    start,
                    end,
                },
            )
            .await
        });

        // Session 1
        let cl = clients[1].clone();
        let response_11 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 0,
                    start,
                    end,
                },
            )
            .await
        });
        let cl = clients[2].clone();
        let response_12 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 1,
                    start,
                    end,
                },
            )
            .await
        });

        // Session 2
        let cl = clients[2].clone();
        let response_22 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 0,
                    start,
                    end,
                },
            )
            .await
        });
        let cl = clients[0].clone();
        let response_20 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 2,
                    start,
                    end,
                },
            )
            .await
        });

        // extra
        let cl = clients[0].clone();
        let response_e0 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 1,
                    start,
                    end,
                },
            )
            .await
        });
        let cl = clients[1].clone();
        let response_e1 = tokio::spawn(async move {
            cl.get_proofs(
                long_context(),
                GetProofsRequest {
                    client_idx: 2,
                    start,
                    end,
                },
            )
            .await
        });

        let (hashes_00, hashes_01) = (response_00.await?.unwrap(), response_01.await?.unwrap());
        let (hashes_11, hashes_12) = (response_11.await?.unwrap(), response_12.await?.unwrap());
        let (hashes_22, hashes_20) = (response_22.await?.unwrap(), response_20.await?.unwrap());
        let (hashes_e0, hashes_e1) = (response_e0.await?.unwrap(), response_e1.await?.unwrap());
        debug_assert_eq!(hashes_00.len(), hashes_01.len());
        debug_assert_eq!(hashes_11.len(), hashes_12.len());
        debug_assert_eq!(hashes_22.len(), hashes_20.len());
        debug_assert_eq!(hashes_e0.len(), hashes_e1.len());

        let verified = plasma::check_hashes(&hashes_e0, &hashes_12)
            & plasma::check_hashes(&hashes_00, &hashes_01)
            & plasma::check_hashes(&hashes_11, &hashes_12)
            & plasma::check_hashes(&hashes_22, &hashes_20)
            & plasma::check_hashes(&hashes_e1, &hashes_22);
        assert!(verified);

        start += cfg.hashes_batch_size;
    }

    let keep =
        collect::KeyCollection::<u64>::keep_values_last(&threshold, &cnt_values_00, &cnt_values_01);

    // Tree prune
    let mut responses = vec![];

    // Session 0
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 0,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 1,
                keep: k,
            },
        )
        .await
    }));

    // Session 1
    let cl = clients[1].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 0,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[2].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 1,
                keep: k,
            },
        )
        .await
    }));

    // Session 2
    let cl = clients[2].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 0,
                keep: k,
            },
        )
        .await
    }));
    let cl = clients[0].clone();
    let k = keep.clone();
    responses.push(tokio::spawn(async move {
        cl.tree_prune(
            long_context(),
            TreePruneRequest {
                client_idx: 2,
                keep: k,
            },
        )
        .await
    }));
    join_all(responses).await;

    // Session 0
    let cl = clients[0].clone();
    let response_0 = tokio::spawn(async move {
        cl.final_shares(long_context(), FinalSharesRequest { client_idx: 0 })
            .await
    });
    let cl = clients[1].clone();
    let response_1 = tokio::spawn(async move {
        cl.final_shares(long_context(), FinalSharesRequest { client_idx: 1 })
            .await
    });
    let (shares_0, shares_1) = (response_0.await?.unwrap(), response_1.await?.unwrap());
    println!(
        "- Time for level {}: {:?}",
        cfg.data_bytes * 8,
        start_last.elapsed().as_secs_f64()
    );
    for res in &collect::KeyCollection::<u64>::final_values(&shares_0, &shares_1) {
        let bits = plasma::bits_to_bitstring(&res.path);
        if res.value > 0 {
            println!("Value ({}) \t Count: {:?}", bits, res.value);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let (cfg, _, num_clients, malicious) = config::get_args("Leader", false, true, true);
    debug_assert!((0.0..0.8).contains(&malicious));
    println!("Running with {}% malicious clients", malicious * 100.0);
    let client_0 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_0.clone(), Bincode::default).await?,
    )
    .spawn();
    let client_1 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_1.clone(), Bincode::default).await?,
    )
    .spawn();
    let client_2 = Client::new(
        client::Config::default(),
        tcp::connect(cfg.server_2.clone(), Bincode::default).await?,
    )
    .spawn();

    let start = Instant::now();
    let keys = generate_keys(&cfg);

    let delta = start.elapsed().as_secs_f64();
    println!(
        "Generated {:?} keys in {:?} seconds ({:?} sec/key)",
        keys[0].0.len(),
        delta,
        delta / (keys[0].0.len() as f64)
    );

    let clients = vec![&client_0, &client_1, &client_2];

    reset_servers(&clients).await?;

    let mut left_to_go = num_clients;
    let reqs_in_flight = 1000;
    while left_to_go > 0 {
        let mut resps = vec![];

        for _ in 0..reqs_in_flight {
            let this_batch = std::cmp::min(left_to_go, cfg.addkey_batch_size);
            left_to_go -= this_batch;

            if this_batch > 0 {
                resps.push(add_keys(&cfg, &clients, &keys, this_batch, malicious));
            }
        }

        for r in resps {
            r.await?;
        }
    }

    tree_init(&clients).await?;

    let start = Instant::now();
    let bit_len = cfg.data_bytes * 8; // bits
    for level in 0..bit_len - 1 {
        let start_level = Instant::now();
        run_level(&cfg, &clients, num_clients).await?;
        println!(
            "- Time for level {}: {:?}",
            level + 1,
            start_level.elapsed().as_secs_f64()
        );
    }
    run_level_last(&cfg, &clients, num_clients).await?;

    println!("Total time {:?}", start.elapsed().as_secs_f64());

    Ok(())
}
