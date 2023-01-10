//! This module contains a version of Balloon-hashing that allows it to be modified into a stream cipher.

use crate::progress::Progress;
use sha3::{digest::FixedOutputReset, Digest, Sha3_512};

/// Balloon hasher state.
#[derive(Debug)]
pub struct Balloon {
    buffer: Vec<[u8; 64]>,
    hash: Sha3_512,    // so that we don't have to generate new hasher every step
    salt: Vec<u8>,     // we need to remember salt for every step
    step_delta: usize, // how many samples to take every step
    cnt: u64,          // used to increase hash complexity
    pos: usize,        // current position for stepping
}

impl Balloon {
    /// Create a new Balloon-Hash instance.
    pub fn new(
        passwd: impl AsRef<[u8]>,
        salt: Vec<u8>,
        s_cost: usize,
        t_cost: usize,
        step_delta: usize,
        prog: Progress,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            assert!(s_cost > 0, "s_cost must be positive");
            assert!(t_cost > 0, "s_cost must be positive");
            assert!(step_delta > 0, "step_delta must be positive");
        }

        let mut res = Self {
            buffer: vec![[0_u8; 64]; s_cost],
            hash: Sha3_512::new(),
            salt,
            step_delta,
            cnt: 0,
            pos: 0,
        };

        prog.set_state("Filling buffer".to_string());
        prog.inc_max(s_cost * t_cost);

        // fill buffer
        res.hash.update(Self::int_to_arr(res.cnt));
        res.cnt += 1;
        res.hash.update(&passwd);
        res.hash.update(&res.salt);
        res.buffer[0] = res.hash.finalize_fixed_reset().into();
        for m in 1..s_cost {
            res.hash.update(Self::int_to_arr(res.cnt));
            res.cnt += 1;
            res.hash.update(res.buffer[m - 1]);
            res.buffer[m] = res.hash.finalize_fixed_reset().into();
        }

        prog.set_state("Mixing buffer".to_string());

        // mix buffer t_cost times
        for _ in 0..t_cost {
            for _ in 0..s_cost {
                res.step_internal(prog.clone());
            }
        }

        res
    }

    /// Steps the internal state. Doing this `s_cost`-times equals one round of buffer mixing.
    ///
    /// # Returns
    /// * Buffer at current position after mixing (before incrementing position).
    fn step_internal(&mut self, prog: Progress) -> [u8; 64] {
        prog.inc();

        let s_cost = self.buffer.len();

        // instead of "self.buffer[(self.pos as i64 - 1).rem_euclid(s_cost as i64) as usize]"
        let prev = if self.pos == 0 {
            self.buffer[s_cost - 1]
        } else {
            self.buffer[self.pos]
        };
        self.hash.update(prev);
        self.hash.update(Self::int_to_arr(self.cnt));
        self.cnt += 1;
        self.hash.update(self.buffer[self.pos]);
        self.buffer[self.pos] = self.hash.finalize_fixed_reset().into();

        for i in 0..self.step_delta {
            self.hash.update(Self::int_to_arr(i as u64));
            self.hash.update(Self::int_to_arr(self.cnt));
            self.cnt += 1;
            self.hash.update(&self.salt);

            // There must be a better way to do this
            let tmp: [u8; 64] = self.hash.finalize_fixed_reset().into();
            let mut tmp2: [u8; 8] = [0u8; 8];
            tmp2.copy_from_slice(&tmp[0..8]);

            let other: usize = Self::arr_to_int(&tmp2).rem_euclid(s_cost as u64) as usize;

            self.hash.update(Self::int_to_arr(self.cnt));
            self.cnt += 1;
            self.hash.update(self.buffer[self.pos]);
            self.hash.update(self.buffer[other]);

            self.buffer[self.pos] = self.hash.finalize_fixed_reset().into();
        }

        let res = self.buffer[self.pos];
        self.pos = (self.pos + 1).rem_euclid(s_cost); // (pos + 1) % s_cost
        res
    }

    /// Same as `step_internal` but uses an additional hash to decouple internal state from outside world.
    pub fn step(&mut self, prog: Progress) -> [u8; 64] {
        let res = self.step_internal(prog);
        self.hash.update(res);
        self.hash.finalize_fixed_reset().into()
    }

    #[inline]
    fn int_to_arr(val: u64) -> [u8; 8] {
        // unsafe { std::mem::transmute::<u64, [u8; 8]>(val) }
        val.to_ne_bytes()
    }
    #[inline]
    fn arr_to_int(arr: &[u8; 8]) -> u64 {
        unsafe { std::mem::transmute::<[u8; 8], u64>(*arr) }
    }
}

#[cfg(test)]
mod tests {
    use crate::progress::Progress;

    use super::Balloon;
    use digest::FixedOutputReset;
    use hex_literal::hex;
    use sha3::{Digest, Sha3_512};

    #[test]
    fn keccak_impl_test() {
        let hash = Sha3_512::new();
        // RHS taken from NIST
        assert_eq!(
            hash.finalize()[..],
            hex!(
                "A6 9F 73 CC A2 3A 9A C5 C8 B5 67 DC 18 5A 75 6E 97 C9 82 16
                 4F E2 58 59 E0 D1 DC C1 47 5C 80 A6 15 B2 12 3A F1 F5 F9 4C
                 11 E3 E9 40 2C 3A C5 58 F5 00 19 9D 95 B6 D3 E3 01 75 85 86
                 28 1D CD 26"
            )
        );
    }

    #[test]
    fn hash_a_reader() {
        let msg: Vec<u8> = vec![1, 2, 3];
        let mut hash = Sha3_512::new();
        hash.update(&msg);
        let res1: [u8; 64] = hash.finalize_fixed_reset().into();
        let mut c = std::io::Cursor::new(msg);
        std::io::copy(&mut c, &mut hash).unwrap();
        let res2: [u8; 64] = hash.finalize_fixed_reset().into();
        assert_eq!(res1, res2);
    }

    #[test]
    fn index_test() {
        let vec = vec![1, 2, 3, 4, 5];
        assert_eq!(vec[(-1i32).rem_euclid(vec.len() as i32) as usize], 5)
    }
    #[test]
    fn index_test_2() {
        assert_eq!((10_usize + 1).rem_euclid(10), 1)
    }

    #[test]
    fn cnt_sanity() {
        for i in 1..5 {
            for k in 1..5 {
                for j in 1..5 {
                    let salt = vec![1, 2, 3];
                    let b = Balloon::new("password", salt, i, j, k, Progress::new());
                    assert_eq!(b.cnt as usize, i + i * j * (k * 2 + 1));
                }
            }
        }
    }
}
