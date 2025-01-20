pub(crate) struct ShaCompressSpongeColumnsView<T: Copy> {
    /// The timestamp at which inputs should be read from memory.
    pub timestamp: T,

    /// hx_i
    pub hx: [T;8],

    /// w[i]
    pub w: [T; 64],

    /// a,b...,h values after compressed
    pub new_a: T,
    pub new_b: T,
    pub new_c: T,
    pub new_d: T,
    pub new_e: T,
    pub new_f: T,
    pub new_g: T,
    pub new_h: T,

    /// output
    pub final_hx: [T;8],

    /// The base address at which we will read the input block.
    pub context: T,
    pub segment: T,
    /// Hx addresses
    pub hx_virt: [T; 8],

    /// W_i addresses
    pub w_virt: [T;64],
}