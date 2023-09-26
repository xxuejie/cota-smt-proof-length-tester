use rand::{rngs::StdRng, Rng, SeedableRng};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, traits::Value,
    SparseMerkleTree, H256,
};
use std::time::SystemTime;

type SMT = SparseMerkleTree<Blake2bHasher, Leaf, DefaultStore<Leaf>>;

#[derive(Default, Clone)]
pub struct Leaf([u8; 32]);

impl Value for Leaf {
    fn to_h256(&self) -> H256 {
        self.0.into()
    }

    fn zero() -> Self {
        Default::default()
    }
}

fn main() {
    let seed: u64 = match std::env::var("SEED") {
        Ok(val) => str::parse(&val).expect("parsing number"),
        Err(_) => SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };
    println!("Seed: {}", seed);

    let mut rng = StdRng::seed_from_u64(seed);

    // let subkey_count = rng.gen_range(100..200);
    // let type_1_key_count = rng.gen_range(20000..30000);
    // let type_2_key_count = rng.gen_range(20000..30000);
    // let type_3_key_count = rng.gen_range(20000..30000);
    let subkey_count = 150;
    let type_1_key_count = 20000;
    let type_2_key_count = 20000;
    let type_3_key_count = 20000;

    println!("Subkey count: {}, type 1 SMT key count: {}, type 2 SMT key count: {}, type 3 SMT key count: {}",
        subkey_count, type_1_key_count, type_2_key_count, type_3_key_count
    );

    let mut tree = SMT::default();

    let mut subkeys: Vec<H256> = (0..subkey_count)
        .map(|_| {
            let ext_data: u32 = rng.gen();
            let mut leaf = [0u8; 32];
            leaf[0] = 0xFF;
            leaf[1] = 0x00;
            leaf[2..8].copy_from_slice(b"subkey");
            leaf[8..12].copy_from_slice(&ext_data.to_le_bytes());
            leaf.into()
        })
        .collect();
    subkeys.dedup();
    println!("Deduped subkey count: {}", subkeys.len());

    for subkey in &subkeys {
        let mut value = Leaf::default();
        rng.fill(&mut value.0);

        tree.update(*subkey, value).expect("update subkey");
    }

    println!("Generating type 1 SMT keys...");
    for _ in 0..type_1_key_count {
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut value = Leaf::default();
        rng.fill(&mut value.0);

        tree.update(key.into(), value)
            .expect("update type 1 SMT key");
    }

    println!("Generating type 2 SMT keys...");
    for _ in 0..type_2_key_count {
        let mut key = [0u8; 32];
        key[0] = 0x81;
        key[1] = 0x00;
        rng.fill(&mut key[2..22]);
        let mut value = Leaf::default();
        rng.fill(&mut value.0);

        tree.update(key.into(), value)
            .expect("update type 2 SMT key");
    }

    println!("Generating type 3 SMT keys...");
    for _ in 0..type_3_key_count {
        let mut key = [0u8; 32];
        key[0] = 0x81;
        key[1] = rng.gen_range(1..=3);
        rng.fill(&mut key[2..26]);
        let mut value = Leaf::default();
        rng.fill(&mut value.0);

        tree.update(key.into(), value)
            .expect("update type 3 SMT key");
    }

    let chosen: usize = rng.gen_range(0..subkeys.len());
    let chosen_key = subkeys[chosen];
    println!("Chosen: {}", chosen);

    let merkle_proof = tree.merkle_proof(vec![chosen_key]).expect("merkle proof");
    let compiled = merkle_proof
        .compile(vec![chosen_key])
        .expect("compile proof");
    assert!(compiled
        .verify::<Blake2bHasher>(
            tree.root(),
            vec![(chosen_key, tree.get(&chosen_key).expect("get").to_h256())]
        )
        .expect("verify"));

    println!("Proof length: {}", compiled.0.len());
}
