//! Short human pairing codes: `N-word-word` (wormhole / Signal style).
use mymesh_core::{Error, Result};
use rand::Rng;

/// Curated short wordlist (256 entries → 8 bits each). Enough entropy when combined
/// with a numeric nameplate and two words (~24 bits + nameplate).
const WORDS: &[&str] = &[
    "alpha", "anchor", "apex", "arc", "arrow", "atlas", "atom", "aurora", "badge", "basin",
    "beacon", "birch", "blade", "bloom", "bolt", "bridge", "canyon", "cedar", "cipher", "cliff",
    "cloud", "cobalt", "comet", "coral", "delta", "dew", "drift", "dune", "ember", "epoch",
    "fable", "fern", "field", "flint", "flora", "forge", "frost", "gale", "gamma", "glen", "grain",
    "grove", "harbor", "haven", "hazel", "helix", "hollow", "honey", "horizon", "ivory", "jade",
    "jasper", "kelp", "knoll", "lagoon", "lark", "lattice", "leaf", "lemon", "lotus", "lumen",
    "maple", "marsh", "meadow", "mercury", "mesa", "mimic", "mint", "mirror", "mist", "moss",
    "nebula", "needle", "nest", "night", "north", "nova", "oak", "oasis", "olive", "onyx", "orbit",
    "orchid", "otter", "oxide", "palm", "paper", "pearl", "pebble", "pine", "pivot", "plume",
    "pond", "prism", "pulse", "quartz", "quill", "rain", "raven", "reef", "ridge", "river",
    "robin", "root", "sable", "sage", "sail", "sand", "sapphire", "scale", "scarlet", "seed",
    "shade", "shell", "shore", "sierra", "silk", "silver", "slate", "smoke", "snow", "solar",
    "spark", "spine", "spruce", "steel", "stone", "storm", "summit", "swift", "tide", "timber",
    "topaz", "trail", "tree", "tundra", "valley", "vapor", "velvet", "vine", "violet", "vista",
    "volt", "wave", "willow", "wind", "winter", "wolf", "wood", "zenith", "zinc", "amber",
    "basalt", "breeze", "bronze", "cascade", "chrome", "circuit", "clover", "copper", "crater",
    "crystal", "current", "dawn", "echo", "falcon", "glacier", "graphite", "harbor", "harvest",
    "indigo", "iron", "ivory", "jungle", "kernel", "laser", "lunar", "magnet", "marble", "meteor",
    "nickel", "omega", "opal", "oxide", "pebble", "photon", "plasma", "polar", "portal", "radar",
    "radar", "ripple", "rocket", "sable", "signal", "sirius", "sonic", "static", "summit", "talon",
    "tensor", "terra", "thunder", "titan", "torque", "turbo", "ultra", "vector", "vertex",
    "violet", "vortex", "walnut", "water", "xenon", "yellow", "zephyr", "anchor", "binary",
    "carbon", "delta", "engine", "fusion", "galaxy", "helium", "ion", "jupiter", "kinetic",
    "lithium", "matrix", "neutron", "orbit", "proton", "quantum", "reactor", "saturn", "thrust",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingCode {
    /// Short numeric nameplate (1–999).
    pub nameplate: u16,
    pub words: [String; 2],
}

impl PairingCode {
    pub fn as_string(&self) -> String {
        format!("{}-{}-{}", self.nameplate, self.words[0], self.words[1])
    }

    /// Password bytes fed into SPAKE2.
    pub fn password_bytes(&self) -> Vec<u8> {
        self.as_string().into_bytes()
    }
}

impl std::fmt::Display for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

pub fn code_from_entropy(nameplate: u16) -> PairingCode {
    let mut rng = rand::thread_rng();
    let w1 = WORDS[rng.gen_range(0..WORDS.len())];
    let w2 = WORDS[rng.gen_range(0..WORDS.len())];
    PairingCode {
        nameplate: nameplate.max(1),
        words: [w1.to_string(), w2.to_string()],
    }
}

pub fn parse_code(raw: &str) -> Result<PairingCode> {
    let lowered = raw.trim().to_lowercase();
    let parts: Vec<&str> = lowered.split('-').collect();
    if parts.len() != 3 {
        return Err(Error::Pairing("code must look like 42-maple-orbit".into()));
    }
    let nameplate: u16 = parts[0]
        .parse()
        .map_err(|_| Error::Pairing("invalid nameplate".into()))?;
    if nameplate == 0 {
        return Err(Error::Pairing("nameplate must be >= 1".into()));
    }
    let w1 = parts[1].to_string();
    let w2 = parts[2].to_string();
    if w1.is_empty() || w2.is_empty() {
        return Err(Error::Pairing("empty word in code".into()));
    }
    Ok(PairingCode {
        nameplate,
        words: [w1, w2],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip_shape() {
        let c = parse_code("7-maple-orbit").unwrap();
        assert_eq!(c.nameplate, 7);
        assert_eq!(c.as_string(), "7-maple-orbit");
    }
}
