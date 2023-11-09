use plasma::{
    collect, config,
    consts::XOF_SIZE,
    prg,
    rpc::{
        AddKeysRequest, Collector, ComputeHashesRequest, FinalSharesRequest, GetMerkleRootsRequest,
        GetProofsRequest, ResetRequest, TreeCrawlLastRequest, TreeCrawlRequest, TreeInitRequest,
        TreePruneRequest,
    },
    Group,
};

use blake3::Hasher;
use futures::{future, prelude::*};
use rayon::prelude::*;
use std::time::Instant;

use std::{
    io,
    sync::{Arc, Mutex},
};
use tarpc::{
    context,
    serde_transport::tcp,
    server::{self, Channel},
    tokio_serde::formats::Bincode,
};
#[derive(Clone)]
struct CollectorServer {
    server_id: i8,
    seed: prg::PrgSeed,
    data_bytes: usize,
    arc: Arc<Mutex<collect::KeyCollection<u64>>>,
}

#[derive(Clone)]
struct BatchCollectorServer {
    cs: Vec<CollectorServer>,
}

#[tarpc::server]
impl Collector for BatchCollectorServer {
    async fn reset(self, _: context::Context, req: ResetRequest) -> String {
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        *coll = collect::KeyCollection::new(
            self.cs[client_idx].server_id,
            &self.cs[client_idx].seed,
            self.cs[client_idx].data_bytes,
        );
        "Done".to_string()
    }

    async fn add_keys(self, _: context::Context, req: AddKeysRequest) -> String {
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        for k in req.keys {
            coll.add_key(k);
        }
        if coll.keys.len() % 10000 == 0 {
            println!(
                "server_id {}) Number of keys: {:?}",
                client_idx,
                coll.keys.len()
            );
        }
        "Done".to_string()
    }

    async fn tree_init(self, _: context::Context, req: TreeInitRequest) -> String {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.tree_init();
        println!(
            "session {:?}: tree_init: {:?}",
            client_idx,
            start.elapsed().as_secs_f64()
        );
        "Done".to_string()
    }

    async fn tree_crawl(self, _: context::Context, req: TreeCrawlRequest) -> Vec<u64> {
        let client_idx = req.client_idx as usize;
        let split_by = req.split_by;
        let malicious = req.malicious;
        let is_last = req.is_last;
        debug_assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();

        coll.tree_crawl(client_idx, split_by, &malicious, is_last)
    }

    async fn get_merkle_roots(
        self,
        _: context::Context,
        req: GetMerkleRootsRequest,
    ) -> (Vec<[u8; XOF_SIZE]>, Vec<usize>) {
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let coll = self.cs[client_idx].arc.lock().unwrap();

        coll.get_merkle_roots(req.start, req.end)
    }

    async fn tree_crawl_last(self, _: context::Context, req: TreeCrawlLastRequest) -> Vec<u64> {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        let res = coll.tree_crawl_last();
        println!(
            "session {:?}: tree_crawl_last: {:?}",
            client_idx,
            start.elapsed().as_secs_f64()
        );
        res
    }

    async fn get_proofs(self, _: context::Context, req: GetProofsRequest) -> Vec<[u8; XOF_SIZE]> {
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let coll = self.cs[client_idx].arc.lock().unwrap();
        debug_assert!(req.start < req.end);

        coll.get_proofs(req.start, req.end)
    }

    async fn tree_prune(self, _: context::Context, req: TreePruneRequest) -> String {
        let client_idx = req.client_idx as usize;
        let mut coll = self.cs[client_idx].arc.lock().unwrap();
        coll.tree_prune(&req.keep);
        "Done".to_string()
    }

    async fn compute_hashes(
        self,
        _: context::Context,
        req: ComputeHashesRequest,
    ) -> Vec<[u8; XOF_SIZE]> {
        let start = Instant::now();
        let client_idx = req.client_idx as usize;
        debug_assert!(client_idx <= 2);
        let coll_0 = self.cs[0].arc.lock().unwrap();
        let coll_1 = self.cs[1].arc.lock().unwrap();
        let coll_2 = self.cs[2].arc.lock().unwrap();
        let (y_0, y_1) = match client_idx {
            0 => (coll_2.get_y_values(), coll_0.get_y_values()),
            1 => (coll_1.get_y_values(), coll_2.get_y_values()),
            _ => panic!("Oh no!"),
        };
        let mut y0_y1: Vec<Vec<u64>> = vec![];
        for i in 0..y_0[0].len() {
            y0_y1.push(
                y_0.par_iter()
                    .zip_eq(y_1.par_iter())
                    .map(|(h0, h1)| {
                        let mut elm = h0[i];
                        elm.sub(&h1[i]);
                        elm
                    })
                    .collect(),
            );
        }
        let mut hashes: Vec<[u8; XOF_SIZE]> = vec![];
        let mut hasher = Hasher::new();
        for y0_y1_client in &y0_y1 {
            for y in y0_y1_client.iter() {
                hasher.update(&y.to_le_bytes());
            }
            hashes.push(
                hasher.finalize().as_bytes()[0..XOF_SIZE]
                    .try_into()
                    .unwrap(),
            );
            hasher.reset();
        }
        println!(
            "session {:?}: compute_hashes: {:?}",
            client_idx,
            start.elapsed().as_secs_f64()
        );

        hashes
    }

    async fn final_shares(
        self,
        _: context::Context,
        req: FinalSharesRequest,
    ) -> Vec<collect::Result<u64>> {
        let client_idx = req.client_idx as usize;
        let coll = self.cs[client_idx].arc.lock().unwrap();
        coll.final_shares()
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let (cfg, server_id, _, _) = config::get_args("Server", true, false, false);
    let server_addr = match server_id {
        0 => cfg.server_0,
        1 => cfg.server_1,
        2 => cfg.server_2,
        _ => panic!("Oh no!"),
    };

    let seeds = vec![
        prg::PrgSeed { key: [1u8; 16] },
        prg::PrgSeed { key: [2u8; 16] },
        prg::PrgSeed { key: [3u8; 16] },
    ];

    let coll_0 = collect::KeyCollection::new(server_id, &seeds[0], cfg.data_bytes * 8);
    let coll_1 = collect::KeyCollection::new(server_id, &seeds[1], cfg.data_bytes * 8);
    let coll_2 = collect::KeyCollection::new(server_id, &seeds[2], cfg.data_bytes * 8);
    let arc_0 = Arc::new(Mutex::new(coll_0));
    let arc_1 = Arc::new(Mutex::new(coll_1));
    let arc_2 = Arc::new(Mutex::new(coll_2));

    println!("Server {} running at {:?}", server_id, server_addr);
    // Listen on any IP
    let listener = tcp::listen(&server_addr, Bincode::default).await?;
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        // Limit channels to 1 per IP.
        .map(|channel| {
            let local_0 = CollectorServer {
                server_id,
                seed: seeds[0].clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc_0.clone(),
            };
            let local_1 = CollectorServer {
                server_id,
                seed: seeds[1].clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc_1.clone(),
            };
            let local_2 = CollectorServer {
                server_id,
                seed: seeds[2].clone(),
                data_bytes: cfg.data_bytes * 8,
                arc: arc_2.clone(),
            };
            let server = BatchCollectorServer {
                cs: vec![local_0, local_1, local_2],
            };

            channel.execute(server.serve())
        })
        // Max 10 channels.
        .buffer_unordered(100)
        .for_each(|_| async {})
        .await;

    Ok(())
}
