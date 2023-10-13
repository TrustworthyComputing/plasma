use crate::dpf;
use crate::prg;
use crate::{xor_in_place, xor_vec};

use bitvec::prelude::*;
use core::convert::TryFrom;
use fast_math::log2_raw;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::Rng;
use rayon::prelude::*;
use rs_merkle::Hasher;
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}

#[derive(Clone)]
struct TreeNode<T> {
    path: Vec<bool>,
    value: T,
    key_states: Vec<dpf::EvalState>,
    key_values: Vec<T>,
}

unsafe impl<T> Send for TreeNode<T> {}
unsafe impl<T> Sync for TreeNode<T> {}

#[derive(Clone)]
pub struct KeyCollection<T> {
    server_id: i8,
    depth: usize,
    pub keys: Vec<(bool, dpf::DPFKey<T>)>,
    frontier: Vec<TreeNode<T>>,
    prev_frontier: Vec<TreeNode<T>>,
    final_proofs: Vec<[u8; 32]>,
    mtree_roots: Vec<[u8; 32]>,
    mtree_indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result<T> {
    pub path: Vec<bool>,
    pub value: T,
}

pub struct Dealer {
    k: Vec<u8>,
    c: u8,
    kc: u8,
}

impl Dealer {
    pub fn new() -> Dealer {
        let mut rng = rand::thread_rng();
        let k = vec![rng.gen::<u8>() % 2, rng.gen::<u8>() % 2];
        let c = rng.gen::<u8>() % 2;
        Dealer {
            kc: k[c as usize],
            k,
            c,
        }
    }
}

impl Default for Dealer {
    fn default() -> Self {
        Self::new()
    }
}

fn is_server_zero_in_session(server_id: i8, session_index: usize) -> bool {
    if ((server_id == 2 || server_id == 1 || server_id == 0) && session_index == 0)
        || (server_id == 0 && session_index == 1)
    {
        return true;
    }

    false
}

impl<T> KeyCollection<T>
where
    T: crate::Share
        + std::fmt::Debug
        + std::cmp::PartialOrd
        + std::convert::From<u32>
        + Send
        + Sync
        + 'static,
{
    pub fn new(server_id: i8, _seed: &prg::PrgSeed, depth: usize) -> KeyCollection<T> {
        KeyCollection::<T> {
            server_id,
            depth,
            keys: vec![],
            frontier: vec![],
            prev_frontier: vec![],
            final_proofs: vec![],
            mtree_roots: vec![],
            mtree_indices: vec![],
        }
    }

    pub fn add_key(&mut self, key: dpf::DPFKey<T>) {
        self.keys.push((true, key));
    }

    pub fn tree_init(&mut self) {
        let mut root = TreeNode::<T> {
            path: vec![],
            value: T::zero(),
            key_states: vec![],
            key_values: vec![],
        };

        for k in &self.keys {
            root.key_states.push(k.1.eval_init());
            root.key_values.push(T::zero());
        }

        self.frontier.clear();
        self.frontier.push(root);
    }

    fn make_tree_node(&self, parent: &TreeNode<T>, dir: bool) -> TreeNode<T> {
        let mut bit_str = crate::bits_to_bitstring(parent.path.as_slice());
        bit_str.push(if dir { '1' } else { '0' });

        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<T>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| key.1.eval_bit(&parent.key_states[i], dir, &bit_str))
            .unzip();

        let mut child_val = T::zero();
        for (i, v) in key_values.iter().enumerate() {
            // Add in only live values
            if self.keys[i].0 {
                child_val.add(v);
            }
        }

        let mut child = TreeNode::<T> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
        };

        child.path.push(dir);

        child
    }

    pub fn tree_crawl(
        &mut self,
        session_index: usize,
        mut split_by: usize,
        malicious: &Vec<usize>,
        is_last: bool,
    ) -> Vec<T> {
        if !malicious.is_empty() {
            if is_last {
                for &malicious_client in malicious {
                    self.keys[malicious_client].0 = false;
                    println!(
                        "SID {}) removing malicious client {}",
                        session_index, malicious_client
                    );
                }
            }
            self.frontier = self.prev_frontier.clone();
        }

        let level = self.frontier[0].path.len();
        debug_assert!(level < self.depth);
        // println!("Level {}", level);

        let next_frontier = self
            .frontier
            .par_iter()
            .flat_map(|node| {
                debug_assert!(node.path.len() <= self.depth);
                let child_0 = self.make_tree_node(node, false);
                let child_1 = self.make_tree_node(node, true);

                vec![child_0, child_1]
            })
            .collect::<Vec<TreeNode<T>>>();

        // Combine the multiple proofs for each client into a single proof for each client.
        let num_clients = next_frontier.get(0).map_or(0, |node| node.key_states.len());
        let mut key_proofs: Vec<_> = vec![[0u8; 32]; num_clients];
        key_proofs
            .par_iter_mut()
            .enumerate()
            .zip_eq(&self.keys)
            .for_each(|((proof_index, proof), key)| {
                if key.0 {
                    for node in next_frontier.iter() {
                        xor_in_place(proof, &node.key_states[proof_index].proof);
                    }
                }
            });

        // For all prefixes, compute the checks for each client.
        let all_y_checks = self
            .frontier
            .par_iter()
            .enumerate()
            .map(|(prefix_index, node)| {
                let node_left = &next_frontier[2 * prefix_index];
                let node_right = &next_frontier[2 * prefix_index + 1];

                debug_assert_eq!(node.key_values.len(), node_left.key_values.len());
                debug_assert_eq!(node.key_values.len(), node_right.key_values.len());

                // For one prefix for all the clients
                node.key_values
                    .par_iter()
                    .enumerate()
                    .map(|(client_index, y_p)| {
                        let y_p0 = &node_left.key_values[client_index];
                        let y_p1 = &node_right.key_values[client_index];

                        let mut value_check = T::zero();
                        if level == 0 {
                            // (1 - server_id) + (-1)^server_id * (- y^{p||0} - y^{p||1})
                            if is_server_zero_in_session(self.server_id, session_index) {
                                value_check.add(&T::one());
                                value_check.sub(y_p0);
                                value_check.sub(y_p1);
                            } else {
                                value_check.add(y_p0);
                                value_check.add(y_p1);
                            }
                        } else {
                            // (-1)^server_id * (y^{p} - y^{p||0} - y^{p||1})
                            if is_server_zero_in_session(self.server_id, session_index) {
                                value_check.add(y_p);
                                value_check.sub(y_p0);
                                value_check.sub(y_p1);
                            } else {
                                value_check.add(y_p0);
                                value_check.add(y_p1);
                                value_check.sub(y_p);
                            }
                        }

                        value_check
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Now, we combine all the checks for each client into a single check for each client.
        let key_checks = all_y_checks[0] // parallelize the clients
            .par_iter()
            .enumerate()
            .zip_eq(&self.keys)
            .map(|((client_index, _), key)| {
                let mut hasher = Sha256::new();
                // If the client is honest.
                if key.0 {
                    all_y_checks.iter().for_each(|checks_for_prefix| {
                        hasher.update(
                            checks_for_prefix[client_index]
                                .clone()
                                .value()
                                .to_le_bytes(),
                        );
                    });
                }
                hasher.finalize().to_vec()
            })
            .collect::<Vec<_>>();

        debug_assert_eq!(key_proofs.len(), key_checks.len());

        let combined_hashes = key_proofs
            .par_iter()
            .zip(key_checks.par_iter())
            .map(|(proof, check)| xor_vec(proof, check).try_into().unwrap())
            .collect::<Vec<[u8; 32]>>();

        // Compute the Merkle tree based on y_checks for each client and the proofs.
        // If we are at the last level, we only need to compute the root as the malicious clients
        // have already been removed.
        if is_last {
            split_by = 1
        };
        let num_leaves = 1 << (combined_hashes.len() as f32).log2().ceil() as usize;
        let chunk_sz = num_leaves / split_by;
        let chunks_list = combined_hashes.chunks(chunk_sz).collect::<Vec<_>>();

        self.mtree_roots = vec![];
        self.mtree_indices = vec![];
        if split_by == 1 {
            let mt = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[0]);
            let root = mt.root().unwrap();
            self.mtree_roots.push(root);
            self.mtree_indices.push(0);
        } else {
            for &i in malicious {
                let mt_left = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[i * 2]);
                let root_left = mt_left.root().unwrap();
                self.mtree_roots.push(root_left);
                self.mtree_indices.push(i * 2);

                if i * 2 + 1 >= chunks_list.len() {
                    continue;
                }
                let mt_right = MerkleTree::<Sha256Algorithm>::from_leaves(chunks_list[i * 2 + 1]);
                let root_right = mt_right.root().unwrap();
                self.mtree_roots.push(root_right);
                self.mtree_indices.push(i * 2 + 1);
            }
        }

        self.prev_frontier = self.frontier.clone();
        self.frontier = next_frontier;

        // These are summed evaluations y for different prefixes.
        self.frontier
            .par_iter()
            .map(|node| node.value.clone())
            .collect::<Vec<T>>()
    }

    pub fn get_merkle_roots(&self, start: usize, mut end: usize) -> (Vec<[u8; 32]>, Vec<usize>) {
        let mut roots = Vec::new();
        let mut indices = Vec::new();

        if end > self.mtree_roots.len() {
            end = self.mtree_roots.len();
        }
        if end > start {
            roots.extend_from_slice(&self.mtree_roots[start..end]);
            indices.extend_from_slice(&self.mtree_indices[start..end]);
        }

        (roots, indices)
    }

    pub fn tree_crawl_last(&mut self) -> Vec<T> {
        let next_frontier = self
            .frontier
            .par_iter()
            .flat_map(|node| {
                let child_0 = self.make_tree_node(node, false);
                let child_1 = self.make_tree_node(node, true);

                vec![child_0, child_1]
            })
            .collect::<Vec<TreeNode<T>>>();

        let num_clients = next_frontier.get(0).map_or(0, |node| node.key_states.len());
        self.final_proofs = vec![[0u8; 32]; num_clients];
        self.final_proofs
            .par_iter_mut()
            .enumerate()
            .zip_eq(&self.keys)
            .for_each(|((proof_index, proof), key)| {
                // If the client is honest.
                if key.0 {
                    for node in next_frontier.iter() {
                        xor_in_place(proof, &node.key_states[proof_index].proof);
                    }
                }
            });

        self.frontier = next_frontier;

        // These are summed evaluations y for different prefixes.
        self.frontier
            .par_iter()
            .map(|node| node.value.clone())
            .collect::<Vec<T>>()
    }

    pub fn get_y_values(&self) -> Vec<&Vec<T>> {
        self.frontier
            .par_iter()
            .map(|node| &node.key_values)
            .collect::<Vec<_>>()
    }

    pub fn get_proofs(&self, start: usize, end: usize) -> Vec<[u8; 32]> {
        let mut proofs = Vec::new();
        if end > start && end <= self.final_proofs.len() {
            proofs.extend_from_slice(&self.final_proofs[start..end]);
        }

        proofs
    }

    pub fn tree_prune(&mut self, alive_vals: &[bool]) {
        debug_assert_eq!(alive_vals.len(), self.frontier.len());

        // Remove from back to front to preserve indices
        for i in (0..alive_vals.len()).rev() {
            if !alive_vals[i] {
                self.frontier.remove(i);
            }
        }

        //println!("Size of frontier: {:?}", self.frontier.len());
    }

    pub fn keep_values(threshold: &T, values_0: &[T], values_1: &[T]) -> Vec<bool> {
        values_0
            .par_iter()
            .zip(values_1.par_iter())
            .map(|(value_0, value_1)| {
                let mut vals_0_one = T::one();
                vals_0_one.add(value_0);

                // Keep nodes that are above threshold
                Self::lt_const((*threshold).clone().value() as u32, &vals_0_one, value_1)
            })
            .collect()
    }

    pub fn secret_share_bool<B>(bit_array: &BitVec<B>, num_bits: usize) -> (BitVec<B>, BitVec<B>)
    where
        B: BitStore,
    {
        let mut rng = rand::thread_rng();
        let mut sh_1 = BitVec::<B>::new();
        let mut sh_2 = BitVec::<B>::new();
        for i in 0..num_bits {
            sh_1.push(rng.gen::<bool>());
            sh_2.push(sh_1[i] ^ bit_array[i]);
        }
        (sh_1, sh_2)
    }

    // P0 is the Sender with inputs (m0, m1)
    // P1 is the Receiver with inputs (b, mb)
    pub fn one_out_of_two_ot(dealer: &Dealer, receiver_b: u8, sender_m: &[u8]) -> u8 {
        let z = receiver_b ^ dealer.c;
        let y = {
            if z == 0 {
                vec![sender_m[0] ^ dealer.k[0], sender_m[1] ^ dealer.k[1]]
            } else {
                vec![sender_m[0] ^ dealer.k[1], sender_m[1] ^ dealer.k[0]]
            }
        };

        y[receiver_b as usize] ^ dealer.kc
    }

    // OR: z = x | y = ~(~x & ~y)
    //   ~(~x & ~y) = ~(~x * ~y) = ~( ~(p0.x + p1.x) * ~(p0.y + p1.y) ) =
    //  ~( (~p0.x + p1.x) * (~p0.y + p1.y) ) =
    //  ~( (~p0.x * ~p0.y) + (~p0.x * p1.y) + (p1.x * ~p0.y) + (p1.x * p1.y) ) =
    //  P0 computes locally ~p0.x * ~p0.y
    //  P1 computes locally p1.x * p1.y
    //  Both parties compute via OT: ~p0.x * p1.y and p1.x * ~p0.y
    pub fn or_gate(x0: bool, y0: bool, x1: bool, y1: bool) -> (bool, bool) {
        let mut rng = rand::thread_rng();

        // Online Phase - P1 receives r0 + p0.x * p1.y
        let r0 = rng.gen::<bool>();
        let dealer = Dealer::new();
        let r0_x0y1 =
            Self::one_out_of_two_ot(&dealer, y1 as u8, &[r0 as u8, (!x0 as u8) ^ (r0 as u8)]) != 0;

        // Online Phase - P0 receives r1 + p1.x * p0.y
        let r1 = rng.gen::<bool>();
        let dealer = Dealer::new();
        let r1_x1y0 =
            Self::one_out_of_two_ot(&dealer, !y0 as u8, &[r1 as u8, (x1 as u8) ^ (r1 as u8)]) != 0;

        // P0
        let share_0 = !((!x0 & !y0) ^ (r0 ^ r1_x1y0));

        // P1
        let share_1 = (x1 & y1) ^ (r1 ^ r0_x0y1);

        (share_0, share_1)
    }

    pub fn get_rand_edabit<B>(num_bits: usize) -> ((T, BitVec<B>), (T, BitVec<B>))
    where
        B: BitStore
            + bitvec::store::BitStore<Unalias = B>
            + Eq
            + Copy
            + std::ops::Rem<Output = B>
            + TryFrom<u32>,
        Standard: Distribution<B>,
        u32: From<B>,
    {
        let mut rng = rand::thread_rng();
        let r = rng.gen::<B>() % B::try_from(64).ok().unwrap();
        let r_bits = r.view_bits::<Lsb0>().to_bitvec();
        let (r_0_bits, r_1_bits) = Self::secret_share_bool(&r_bits, num_bits);
        let (r_0, r_1) = T::from(u32::from(r)).share();
        ((r_0, r_0_bits), (r_1, r_1_bits))
    }

    // Returns c = x < R
    fn lt_bits<B>(const_r: u32, sh_0: &BitVec<B>, sh_1: &BitVec<B>) -> (u8, u8)
    where
        B: BitStore,
    {
        let r_bits = const_r.view_bits::<Lsb0>().to_bitvec();
        let num_bits = sh_0.len();

        // Step 1
        let mut y_bits_0 = bitvec![B, Lsb0; 0; num_bits];
        let mut y_bits_1 = bitvec![B, Lsb0; 0; num_bits];
        for i in 0..num_bits {
            y_bits_0.set(i, sh_0[i] ^ r_bits[i]);
            y_bits_1.set(i, sh_1[i]);
        }
        // Step 2 - PreOpL
        let log_m = log2_raw(num_bits as f32).ceil() as usize;
        for i in 0..log_m {
            for j in 0..(num_bits / (1 << (i + 1))) {
                let y = ((1 << i) + j * (1 << (i + 1))) - 1;
                for z in 1..(1 << (i + 1)) {
                    if y + z < num_bits {
                        let idx_y = num_bits - 1 - y;
                        let (or_0, or_1) = Self::or_gate(
                            y_bits_0[idx_y],
                            y_bits_0[idx_y - z],
                            y_bits_1[idx_y],
                            y_bits_1[idx_y - z],
                        );
                        y_bits_0.set(idx_y - z, or_0);
                        y_bits_1.set(idx_y - z, or_1);
                    }
                }
            }
        }
        y_bits_0.push(false);
        y_bits_1.push(false);
        let z_bits_0 = y_bits_0;
        let z_bits_1 = y_bits_1;

        // Step 3
        let mut w_bits_0 = bitvec![B, Lsb0; 0; num_bits];
        let mut w_bits_1 = bitvec![B, Lsb0; 0; num_bits];
        for i in 0..num_bits {
            w_bits_0.set(i, z_bits_0[i] ^ z_bits_0[i + 1]); // -
            w_bits_1.set(i, z_bits_1[i] ^ z_bits_1[i + 1]); // -
        }

        // Step 4
        let mut sum_0 = 0u8;
        let mut sum_1 = 0u8;
        for i in 0..num_bits {
            sum_0 += if r_bits[i] & w_bits_0[i] { 1 } else { 0 };
            sum_1 += if r_bits[i] & w_bits_1[i] { 1 } else { 0 };
        }

        (
            sum_0.view_bits::<Lsb0>().to_bitvec()[0] as u8,
            sum_1.view_bits::<Lsb0>().to_bitvec()[0] as u8,
        )
    }

    fn lt_const(const_r: u32, x_0: &T, x_1: &T) -> bool {
        let num_bits = 16;
        let ((r_0, r_0_bits), (r_1, r_1_bits)) = Self::get_rand_edabit::<u16>(num_bits);
        let const_m = (1 << num_bits) - 1;

        // Step 1
        let mut a_0 = T::zero();
        a_0.add(x_0);
        a_0.add(&r_0);

        let mut a_1 = T::zero();
        a_1.add(x_1);
        a_1.add(&r_1);

        let b_0 = a_0.clone();
        let mut b_1 = a_1.clone();
        let const_r_fe = T::from(const_m - const_r);
        b_1.add(&const_r_fe);

        // Step 2
        let mut a = T::zero();
        a.add(&a_0);
        a.add(&a_1);

        let mut b = T::zero();
        b.add(&b_0);
        b.add(&b_1);

        // Step 3
        let (w1_0, w1_1) = Self::lt_bits(a.clone().value() as u32, &r_0_bits, &r_1_bits);
        let (w2_0, w2_1) = Self::lt_bits(b.clone().value() as u32, &r_0_bits, &r_1_bits);
        let w1 = w1_0 ^ w1_1;
        let w2 = w2_0 ^ w2_1;
        let w3 = (b.clone().value() as u16) < (const_m - const_r) as u16;

        let w1_val = w1 as i8;
        let w2_val = w2 as i8;
        let w3_val = w3 as i8;
        let c = 1 - (w1_val - w2_val + w3_val);

        // if cfg!(debug_assertions) {
        //     println!("\tR: {}", const_r);
        //     println!("\tM: {}", const_m);
        //     println!("\tb.value() {} < M - R: {}", b.clone().value() as u8, const_m - const_r as u32);
        //     println!("\ta u8: {}", a.clone().value() as u8);
        //     println!("\tb u8: {}", b.clone().value() as u8);
        //     println!("\tw1_val: {}", w1_val);
        //     println!("\tw2_val: {}", w2_val);
        //     println!("\tw3_val: {}", w3_val);
        //     println!("\tw: x < {} : {}", const_r, c % 2);
        // }

        c % 2 == 0
    }

    pub fn keep_values_last(threshold: &T, cnt_values_0: &[T], cnt_values_1: &[T]) -> Vec<bool> {
        debug_assert_eq!(cnt_values_0.len(), cnt_values_1.len());

        cnt_values_0
            .par_iter()
            .zip(cnt_values_1.par_iter())
            .map(|(value_0, value_1)| {
                let mut v = T::zero();
                v.add(value_0);
                v.add(value_1);

                v >= *threshold
            })
            .collect::<Vec<_>>()
    }

    pub fn final_shares(&self) -> Vec<Result<T>> {
        self.frontier
            .par_iter()
            .map(|n| Result::<T> {
                path: n.path.clone(),
                value: n.value.clone(),
            })
            .collect::<Vec<_>>()
    }

    // Reconstruct counters based on shares
    pub fn final_values(results_0: &[Result<T>], results_1: &[Result<T>]) -> Vec<Result<T>> {
        debug_assert_eq!(results_0.len(), results_1.len());

        results_0
            .par_iter()
            .zip(results_1.par_iter())
            .map(|(r0, r1)| {
                debug_assert_eq!(r0.path, r1.path);

                let mut v = T::zero();
                v.add(&r0.value);
                v.add(&r1.value);

                Result {
                    path: r0.path.clone(),
                    value: v,
                }
            })
            .filter(|result| result.value > T::zero())
            .collect::<Vec<_>>()
    }
}
