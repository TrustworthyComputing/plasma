use crate::prg;
use crate::xor_vec;
use crate::Group;

use crate::consts::XOF_SIZE;
use blake3::Hasher;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CorWord<T> {
    seed: prg::PrgSeed,
    bits: (bool, bool),
    word: T,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DPFKey<T> {
    pub key_idx: bool,
    root_seed: prg::PrgSeed,
    cor_words: Vec<CorWord<T>>,
    pub cs: Vec<[u8; XOF_SIZE]>,
}

#[derive(Clone, Debug)]
pub struct EvalState {
    level: usize,
    pub seed: prg::PrgSeed,
    pub bit: bool,
    pub proof: [u8; XOF_SIZE],
}

trait TupleMapToExt<T, U> {
    type Output;
    fn map<F: FnMut(&T) -> U>(&self, f: F) -> Self::Output;
}

type TupleMutIter<'a, T> =
    std::iter::Chain<std::iter::Once<(bool, &'a mut T)>, std::iter::Once<(bool, &'a mut T)>>;

trait TupleExt<T> {
    fn map_mut<F: Fn(&mut T)>(&mut self, f: F);
    fn get(&self, val: bool) -> &T;
    fn get_mut(&mut self, val: bool) -> &mut T;
    fn iter_mut(&mut self) -> TupleMutIter<T>;
}

impl<T, U> TupleMapToExt<T, U> for (T, T) {
    type Output = (U, U);

    #[inline(always)]
    fn map<F: FnMut(&T) -> U>(&self, mut f: F) -> Self::Output {
        (f(&self.0), f(&self.1))
    }
}

impl<T> TupleExt<T> for (T, T) {
    #[inline(always)]
    fn map_mut<F: Fn(&mut T)>(&mut self, f: F) {
        f(&mut self.0);
        f(&mut self.1);
    }

    #[inline(always)]
    fn get(&self, val: bool) -> &T {
        match val {
            false => &self.0,
            true => &self.1,
        }
    }

    #[inline(always)]
    fn get_mut(&mut self, val: bool) -> &mut T {
        match val {
            false => &mut self.0,
            true => &mut self.1,
        }
    }

    fn iter_mut(&mut self) -> TupleMutIter<T> {
        std::iter::once((false, &mut self.0)).chain(std::iter::once((true, &mut self.1)))
    }
}

fn gen_cor_word<W>(
    bit: bool,
    value: W,
    bits: &mut (bool, bool),
    seeds: &mut (prg::PrgSeed, prg::PrgSeed),
) -> CorWord<W>
where
    W: prg::FromRng + Clone + Group + std::fmt::Debug,
{
    let data = seeds.map(|s| s.expand());

    // If alpha[i] = 0:
    //   Keep = L,  Lose = R
    // Else
    //   Keep = R,  Lose = L
    let keep = bit;
    let lose = !keep;

    let mut cw = CorWord {
        seed: data.0.seeds.get(lose) ^ data.1.seeds.get(lose),
        bits: (
            data.0.bits.0 ^ data.1.bits.0 ^ bit ^ true,
            data.0.bits.1 ^ data.1.bits.1 ^ bit,
        ),
        word: W::zero(),
    };

    for (b, seed) in seeds.iter_mut() {
        *seed = data.get(b).seeds.get(keep).clone();

        if *bits.get(b) {
            *seed = &*seed ^ &cw.seed;
        }

        let mut newbit = *data.get(b).bits.get(keep);
        if *bits.get(b) {
            newbit ^= cw.bits.get(keep);
        }

        *bits.get_mut(b) = newbit;
    }

    let converted = seeds.map(|s| s.convert());
    cw.word = value;
    cw.word.sub(&converted.0.word);
    cw.word.add(&converted.1.word);

    if bits.1 {
        cw.word.negate();
    }

    seeds.0 = converted.0.seed;
    seeds.1 = converted.1.seed;

    cw
}

/// All-prefix DPF implementation.
impl<T> DPFKey<T>
where
    T: prg::FromRng + Clone + Group + std::fmt::Debug,
{
    pub fn gen(alpha_bits: &[bool], values: &[T]) -> (DPFKey<T>, DPFKey<T>) {
        debug_assert!(alpha_bits.len() == values.len() + 1);

        let root_seeds = (prg::PrgSeed::random(), prg::PrgSeed::random());
        let root_bits = (false, true);

        let mut seeds = root_seeds.clone();
        let mut bits = root_bits;

        let mut cor_words: Vec<CorWord<T>> = Vec::new();
        let mut cs: Vec<[u8; XOF_SIZE]> = Vec::new();
        let mut bit_str = "".to_string();
        let mut hasher = Hasher::new();
        for i in 0..alpha_bits.len() {
            let bit = alpha_bits[i];
            bit_str.push_str(if bit { "1" } else { "0" });
            let cw = gen_cor_word::<T>(bit, values[i].clone(), &mut bits, &mut seeds);
            cor_words.push(cw);

            let pi_0 = {
                hasher.reset();
                hasher.update_rayon(bit_str.as_bytes());
                hasher.update_rayon(&seeds.0.key);
                hasher.finalize()
            };
            let pi_1 = {
                hasher.reset();
                hasher.update_rayon(bit_str.as_bytes());
                hasher.update_rayon(&seeds.1.key);
                hasher.finalize()
            };
            cs.push(
                xor_vec(&pi_0.as_bytes()[..XOF_SIZE], &pi_1.as_bytes()[..XOF_SIZE])[..XOF_SIZE]
                    .try_into()
                    .unwrap(),
            );
        }

        (
            DPFKey::<T> {
                key_idx: false,
                root_seed: root_seeds.0,
                cor_words: cor_words.clone(),
                cs: cs.clone(),
            },
            DPFKey::<T> {
                key_idx: true,
                root_seed: root_seeds.1,
                cor_words,
                cs,
            },
        )
    }

    pub fn eval_bit(&self, state: &EvalState, dir: bool, bit_str: &String) -> (EvalState, T) {
        let tau = state.seed.expand_dir(!dir, dir);
        let mut seed = tau.seeds.get(dir).clone();
        let mut new_bit = *tau.bits.get(dir);

        if state.bit {
            seed = &seed ^ &self.cor_words[state.level].seed;
            new_bit ^= self.cor_words[state.level].bits.get(dir);
        }

        let converted = seed.convert::<T>();
        let new_seed = converted.seed;

        let mut word = converted.word;
        if new_bit {
            word.add(&self.cor_words[state.level].word);
        }

        if self.key_idx {
            word.negate()
        }

        // Compute proofs
        let h2 = {
            let mut hasher = Hasher::new();
            hasher.update_rayon(bit_str.as_bytes());
            hasher.update_rayon(&new_seed.key);
            let pi_prime = hasher.finalize();

            let h: [u8; XOF_SIZE] = if !new_bit {
                pi_prime.as_bytes()[..XOF_SIZE].try_into().unwrap()
            } else {
                xor_vec(&self.cs[state.level], &pi_prime.as_bytes()[..XOF_SIZE])[..XOF_SIZE]
                    .try_into()
                    .unwrap()
            };
            hasher.reset();
            hasher.update_rayon(&h);
            hasher.finalize()
        };
        let proof = xor_vec(h2.as_bytes(), &state.proof)
            .as_slice()
            .try_into()
            .unwrap();

        (
            EvalState {
                level: state.level + 1,
                seed: new_seed,
                bit: new_bit,
                proof,
            },
            word,
        )
    }

    pub fn eval_init(&self) -> EvalState {
        EvalState {
            level: 0,
            seed: self.root_seed.clone(),
            bit: self.key_idx,
            proof: [0u8; XOF_SIZE],
        }
    }

    pub fn eval(&self, idx: &[bool], pi: &mut [u8; XOF_SIZE]) -> (Vec<T>, T) {
        debug_assert!(idx.len() <= self.domain_size());
        debug_assert!(!idx.is_empty());
        let mut out = vec![];
        let mut state = self.eval_init();

        let mut bit_str: String = "".to_string();
        state.proof = *pi;

        for &bit in idx.iter().take(idx.len() - 1) {
            bit_str.push(if bit { '1' } else { '0' });

            let (state_new, word) = self.eval_bit(&state, bit, &bit_str);
            out.push(word);
            state = state_new;
        }

        let (_, last) = self.eval_bit(&state, *idx.last().unwrap(), &bit_str);
        *pi = state.proof;

        (out, last)
    }

    pub fn gen_from_str(s: &str) -> (Self, Self) {
        let bits = crate::string_to_bits(s);
        let values = vec![T::one(); bits.len()];
        DPFKey::gen(&bits, &values)
    }

    pub fn domain_size(&self) -> usize {
        self.cor_words.len()
    }
}
