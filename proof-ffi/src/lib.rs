//! C ABI for constructing keyed multileaf Merkle proofs and serializing PlainProof.

use blake3::CHUNK_LEN;

const FIXED_RANK: usize = 128;
use pearl_blake3::MerkleTree;
use zk_pow::ffi::plain_proof::{MatrixMerkleProof, PlainProof};

use std::sync::{Mutex, OnceLock};

static PROOF_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
type BProver = Box<dyn Fn(&[usize], usize) -> MatrixMerkleProof + Send>;
struct BCache {
    generation: u64,
    address: usize,
    n: usize,
    k: usize,
    key: [u8; 32],
    prove: BProver,
}
static B_CACHE: Mutex<Option<BCache>> = Mutex::new(None);

/// Configure before starting proof work. No global Rayon pool is used by miner.
#[no_mangle]
pub extern "C" fn proof_set_threads(threads: usize) -> i32 {
    if threads == 0 || PROOF_POOL.get().is_some() { return -1; }
    match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
        Ok(pool) => if PROOF_POOL.set(pool).is_ok() { 0 } else { -1 },
        Err(_) => -1,
    }
}

/// Caller must drain queued proofs, then call this BEFORE writing or freeing B.
/// Dropping the closure releases the tree and any references it retains to B.
#[no_mangle]
pub extern "C" fn proof_clear_b_cache() {
    *B_CACHE.lock().unwrap() = None;
}

fn cached_b_proof(b: &'static [u8], key: [u8; 32], rows: &[usize],
                  n: usize, k: usize, generation: u64) -> MatrixMerkleProof {
    let mut cache = B_CACHE.lock().unwrap();
    let hit = cache.as_ref().map_or(false, |c| c.generation == generation
        && c.address == b.as_ptr() as usize && c.n == n && c.k == k && c.key == key);
    if !hit {
        // Bound memory to one B tree; release the old tree before building anew.
        *cache = None;
        let tree = MerkleTree::new(b, key);
        let prove = Box::new(move |rows: &[usize], cols: usize| {
            let leaves = leaf_indices_from_rows(rows, cols);
            let p = tree.get_multileaf_proof(&leaves);
            MatrixMerkleProof::new(p.leaf_data, p.leaf_indices, rows.to_vec(),
                                  p.total_leaves, p.root, p.siblings)
        });
        *cache = Some(BCache { generation, address: b.as_ptr() as usize, n, k, key, prove });
    }
    (cache.as_ref().unwrap().prove)(rows, k)
}

fn leaf_indices_from_rows(rows: &[usize], cols: usize) -> Vec<usize> {
    MerkleTree::compute_leaf_indices_from_rows(rows, (0, cols))
}

fn matrix_proof(data: &[u8], key: [u8; 32], rows: &[usize], cols: usize) -> MatrixMerkleProof {
    let tree = MerkleTree::new(data, key);
    let leaves = leaf_indices_from_rows(rows, cols);
    let p = tree.get_multileaf_proof(&leaves);
    MatrixMerkleProof::new(
        p.leaf_data,
        p.leaf_indices,
        rows.to_vec(),
        p.total_leaves,
        p.root,
        p.siblings,
    )
}

/// Bind the incomplete header to the exact mining configuration via BLAKE3.
/// The caller must provide valid pointers and a writable 32-byte `out` buffer.
#[no_mangle]
pub unsafe extern "C" fn hash_key(
    header: *const u8,
    header_len: usize,
    common_dim: usize,
    rows_pat: *const usize,
    n_rows: usize,
    cols_pat: *const usize,
    n_cols: usize,
    out: *mut u8,
) -> i32 {
    use zk_pow::api::proof::{MMAType, MiningConfiguration, PeriodicPattern};
    let rows: Vec<u32> = std::slice::from_raw_parts(rows_pat, n_rows)
        .iter().map(|&v| v as u32).collect();
    let cols: Vec<u32> = std::slice::from_raw_parts(cols_pat, n_cols)
        .iter().map(|&v| v as u32).collect();
    let cfg = MiningConfiguration {
        common_dim: common_dim as u32,
        rank: FIXED_RANK as u16,
        mma_type: MMAType::Int7xInt7ToInt32,
        rows_pattern: PeriodicPattern::from_list(&rows).unwrap(),
        cols_pattern: PeriodicPattern::from_list(&cols).unwrap(),
        moe: None,
    };
    let mut h = blake3::Hasher::new();
    h.update(std::slice::from_raw_parts(header, header_len));
    h.update(&cfg.to_bytes());
    std::ptr::copy_nonoverlapping(h.finalize().as_bytes().as_ptr(), out, 32);
    0
}

/// Serialize a PlainProof, optionally retaining a B tree for a nonzero generation.
/// Return length, or -1 if cap is insufficient. B must remain allocated and
/// immutable until proof_clear_b_cache(), even after this call returns. Other
/// pointers must remain valid for this call; out must be writable for cap bytes.
#[no_mangle]
pub unsafe extern "C" fn build_proof_bin_cached_b(
    a: *const u8,
    b: *const u8,
    m: usize,
    n: usize,
    k: usize,
    key: *const u8,
    a_rows: *const usize,
    na: usize,
    b_cols: *const usize,
    nb: usize,
    out: *mut u8,
    cap: usize,
    b_generation: u64,
) -> isize {
    assert!((m * k) % CHUNK_LEN == 0 && (n * k) % CHUNK_LEN == 0);
    let a = std::slice::from_raw_parts(a, m * k);
    // The cached ABI borrows B across calls. Its owner must keep B immutable
    // and allocated until proof_clear_b_cache() after draining all proofs.
    let b: &'static [u8] = std::slice::from_raw_parts(b, n * k);
    let mut key32 = [0u8; 32];
    key32.copy_from_slice(std::slice::from_raw_parts(key, 32));
    let a_rows = std::slice::from_raw_parts(a_rows, na);
    let b_cols = std::slice::from_raw_parts(b_cols, nb);

    // The row/column proof indices refer to the original matrices, not their
    // noised forms used by the NPU scan.
    let make_bin = || {
        let proof = PlainProof {
            m, n, k,
            noise_rank: FIXED_RANK,
            a: matrix_proof(a, key32, a_rows, k),
            bt: if b_generation == 0 {
                matrix_proof(b, key32, b_cols, k)
            } else {
                cached_b_proof(b, key32, b_cols, n, k, b_generation)
            },
            moe: None,
        };
        bincode::serialize(&proof).unwrap()
    };
    let bin = match PROOF_POOL.get() {
        Some(pool) => pool.install(make_bin),
        None => make_bin(),
    };
    if bin.len() > cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bin.as_ptr(), out, bin.len());
    bin.len() as isize
}

/// Original ABI, without persistent B references.
#[no_mangle]
pub unsafe extern "C" fn build_proof_bin(
    a: *const u8,
    b: *const u8,
    m: usize,
    n: usize,
    k: usize,
    key: *const u8,
    a_rows: *const usize,
    na: usize,
    b_cols: *const usize,
    nb: usize,
    out: *mut u8,
    cap: usize,
) -> isize {
    build_proof_bin_cached_b(a, b, m, n, k, key, a_rows, na,
                             b_cols, nb, out, cap, 0)
}
