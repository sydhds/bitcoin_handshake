use bitflags::bitflags;

#[derive(Debug, Clone, PartialEq)]
pub struct Services(i64);

bitflags! {
    impl Services: i64 {
        /// This node can be asked for full blocks instead of just headers.
        const NODE_NETWORK = 1;
        /// See BIP 0064
        const NODE_GETUTXO = 2;
        /// See BIP 0111
        const NODE_BLOOM  = 4;
        /// See BIP 0144
        const NODE_WITNESS = 8;
        /// Never formally proposed (as a BIP), and discontinued.
        /// Was historically sporadically seen on the network.
        const NODE_XTHIN = 16;
        /// See BIP 0157
        const NODE_COMPACT_FILTERS = 64;
        /// See BIP 0159
        const NODE_NETWORK_LIMITED = 1024;
    }
}
