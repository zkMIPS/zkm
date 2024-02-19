#![allow(clippy::enum_variant_names)]

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Debug)]
pub(crate) enum GlobalMetadata {
    /// A pointer to the root of the state trie within the `TrieData` buffer.
    StateTrieRoot = 0,
    // The root digests of each Merkle trie before these transactions.
    StateTrieRootDigestBefore = 1,
    // The root digests of each Merkle trie after these transactions.
    StateTrieRootDigestAfter = 2,
}

impl GlobalMetadata {
    pub(crate) const COUNT: usize = 3;

    pub(crate) const fn all() -> [Self; Self::COUNT] {
        [
            Self::StateTrieRoot,
            Self::StateTrieRootDigestBefore,
            Self::StateTrieRootDigestAfter,
        ]
    }

    /// The variable name that gets passed into kernel assembly code.
    pub(crate) const fn var_name(&self) -> &'static str {
        match self {
            Self::StateTrieRoot => "GLOBAL_METADATA_STATE_TRIE_ROOT",
            Self::StateTrieRootDigestBefore => "GLOBAL_METADATA_STATE_TRIE_DIGEST_BEFORE",
            Self::StateTrieRootDigestAfter => "GLOBAL_METADATA_STATE_TRIE_DIGEST_AFTER",
        }
    }
}
