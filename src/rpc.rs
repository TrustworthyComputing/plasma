use crate::collect;
use crate::consts::XOF_SIZE;
use crate::dpf;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResetRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddKeysRequest {
    pub client_idx: u8,
    pub keys: Vec<dpf::DPFKey<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeInitRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeCrawlRequest {
    pub client_idx: u8,
    pub split_by: usize,
    pub malicious: Vec<usize>,
    pub is_last: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeCrawlLastRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreePruneRequest {
    pub client_idx: u8,
    pub keep: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetProofsRequest {
    pub client_idx: u8,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetMerkleRootsRequest {
    pub client_idx: u8,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeHashesRequest {
    pub client_idx: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalSharesRequest {
    pub client_idx: u8,
}

#[tarpc::service]
pub trait Collector {
    async fn reset(rst: ResetRequest) -> String;
    async fn add_keys(add: AddKeysRequest) -> String;
    async fn tree_init(req: TreeInitRequest) -> String;
    async fn tree_crawl(req: TreeCrawlRequest) -> Vec<u64>;
    async fn tree_crawl_last(req: TreeCrawlLastRequest) -> Vec<u64>;
    async fn get_proofs(req: GetProofsRequest) -> Vec<[u8; XOF_SIZE]>;
    async fn get_merkle_roots(req: GetMerkleRootsRequest) -> (Vec<[u8; XOF_SIZE]>, Vec<usize>);
    async fn tree_prune(req: TreePruneRequest) -> String;
    async fn compute_hashes(req: ComputeHashesRequest) -> Vec<[u8; XOF_SIZE]>;
    async fn final_shares(req: FinalSharesRequest) -> Vec<collect::Result<u64>>;
}
