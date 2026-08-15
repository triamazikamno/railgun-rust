//! Address-specific `RelayAdapt7702` compatibility metadata.
//!
//! This module contains frozen package configuration evidence only. It does
//! not read a registry or an RPC endpoint and it never replaces a configured
//! transaction target.

use alloy::primitives::{Address, address};

/// The execute ABI kind for a deployment, without an execution nonce value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayAdapt7702ExecutionVersionKind {
    /// The current nonce-aware `execute` ABI.
    CurrentNonceAware,
    /// The legacy `execute` ABI without an execute nonce argument.
    LegacyPreExecuteNonce,
}

/// Evidence class attached to a `RelayAdapt7702` metadata record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayAdapt7702EvidenceClass {
    /// A frozen package configuration assertion, not deployment safety proof.
    FrozenPackageConfigurationAssertion,
    /// ABI compatibility evidence without a source or deployment equivalence claim.
    AbiCompatibilityEvidence,
    /// An observed historical address whose ABI version is not proven.
    HistoricalAddressObservation,
    /// Explicit downstream configuration supplied for this target.
    ExplicitConfiguration,
    /// Reserved for a later, separately proven on-chain conformance result.
    DeploymentConformance,
}

/// Provenance and limitations for one metadata record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdapt7702Provenance {
    pub source: &'static str,
    pub reference: &'static str,
    pub limitations: &'static str,
}

const PACKAGE_CONFIGURATION_LIMITATIONS: &str = "Frozen package configuration and ABI compatibility evidence only; this does not prove deployed bytecode, immutable values, source safety, deployment safety, implementation identity, or address equivalence.";

const HISTORICAL_ADDRESS_LIMITATIONS: &str = "Historical address observation only; list order does not prove an ABI version, and no source, bytecode, immutable, deployment, or address-equivalence claim is made.";

const EXPLICIT_CONFIGURATION_LIMITATIONS: &str = "Explicit reviewed or configured metadata is authoritative for this target; it is not independently verified by sync-service and is not deployment-bytecode or source safety proof.";

const PACKAGE_PROVENANCE: RelayAdapt7702Provenance = RelayAdapt7702Provenance {
    source: "@railgun-community/shared-models@8.1.0-rc.1",
    reference: "relayAdapt7702Contract and relayAdapt7702SupportsExecuteNonce package configuration",
    limitations: PACKAGE_CONFIGURATION_LIMITATIONS,
};

const REGISTRY_PROVENANCE: RelayAdapt7702Provenance = RelayAdapt7702Provenance {
    source: "@railgun-community/shared-models@8.1.0-rc.1",
    reference: "observed RelayAdapt7702 registry address package configuration",
    limitations: PACKAGE_CONFIGURATION_LIMITATIONS,
};

const HISTORICAL_PROVENANCE: RelayAdapt7702Provenance = RelayAdapt7702Provenance {
    source: "railgun-rust pre-7702 ChainConfigDefaults",
    reference: "historical relay_adapt_7702_contract default observation",
    limitations: HISTORICAL_ADDRESS_LIMITATIONS,
};

const EXPLICIT_PROVENANCE: RelayAdapt7702Provenance = RelayAdapt7702Provenance {
    source: "downstream configuration",
    reference: "explicit RelayAdapt7702 execution version supplied by the caller",
    limitations: EXPLICIT_CONFIGURATION_LIMITATIONS,
};

/// Address-specific metadata returned by the construction resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdapt7702AddressMetadata {
    pub address: Address,
    pub construction_version: Option<RelayAdapt7702ExecutionVersionKind>,
    pub evidence_class: RelayAdapt7702EvidenceClass,
    pub provenance: RelayAdapt7702Provenance,
}

impl RelayAdapt7702AddressMetadata {
    #[must_use]
    pub const fn construction_version(self) -> Option<RelayAdapt7702ExecutionVersionKind> {
        self.construction_version
    }
}

/// The current package-configured `RelayAdapt7702` address and its proven kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdapt7702CurrentMetadata {
    pub address: Address,
    pub execution_version: RelayAdapt7702ExecutionVersionKind,
    pub evidence_class: RelayAdapt7702EvidenceClass,
    pub provenance: RelayAdapt7702Provenance,
}

impl RelayAdapt7702CurrentMetadata {
    #[must_use]
    pub const fn address_metadata(self) -> RelayAdapt7702AddressMetadata {
        RelayAdapt7702AddressMetadata {
            address: self.address,
            construction_version: Some(self.execution_version),
            evidence_class: self.evidence_class,
            provenance: self.provenance,
        }
    }
}

/// Advisory registry address for a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdapt7702AdvisoryRegistryMetadata {
    pub address: Address,
    pub evidence_class: RelayAdapt7702EvidenceClass,
    pub provenance: RelayAdapt7702Provenance,
}

/// A known historical address. Its position in this list never supplies a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdapt7702HistoricalMetadata {
    pub address: Address,
    pub construction_version: Option<RelayAdapt7702ExecutionVersionKind>,
    pub evidence_class: RelayAdapt7702EvidenceClass,
    pub provenance: RelayAdapt7702Provenance,
}

impl RelayAdapt7702HistoricalMetadata {
    #[must_use]
    pub const fn address_metadata(self) -> RelayAdapt7702AddressMetadata {
        RelayAdapt7702AddressMetadata {
            address: self.address,
            construction_version: self.construction_version,
            evidence_class: self.evidence_class,
            provenance: self.provenance,
        }
    }
}

/// All static `RelayAdapt7702` metadata for one supported chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAdapt7702ChainMetadata {
    pub chain_id: u64,
    current: RelayAdapt7702CurrentMetadata,
    advisory_registry: RelayAdapt7702AdvisoryRegistryMetadata,
    known_history: &'static [RelayAdapt7702HistoricalMetadata],
}

impl RelayAdapt7702ChainMetadata {
    #[must_use]
    pub const fn current(self) -> RelayAdapt7702CurrentMetadata {
        self.current
    }

    #[must_use]
    pub const fn advisory_registry(self) -> RelayAdapt7702AdvisoryRegistryMetadata {
        self.advisory_registry
    }

    #[must_use]
    pub const fn known_history(self) -> &'static [RelayAdapt7702HistoricalMetadata] {
        self.known_history
    }

    #[must_use]
    pub fn address_metadata(self, address: Address) -> Option<RelayAdapt7702AddressMetadata> {
        if address == self.current.address {
            return Some(self.current.address_metadata());
        }

        self.known_history
            .iter()
            .find(|entry| entry.address == address)
            .map(|entry| entry.address_metadata())
    }
}

const ETHEREUM_CURRENT: RelayAdapt7702CurrentMetadata = RelayAdapt7702CurrentMetadata {
    address: address!("0x05aE73C5925d843864AE6f261f3175dE2ebCd963"),
    execution_version: RelayAdapt7702ExecutionVersionKind::CurrentNonceAware,
    evidence_class: RelayAdapt7702EvidenceClass::FrozenPackageConfigurationAssertion,
    provenance: PACKAGE_PROVENANCE,
};

const BNB_CURRENT: RelayAdapt7702CurrentMetadata = RelayAdapt7702CurrentMetadata {
    address: address!("0x48cf4b897f64D81212c1423D78a05E828d0cE19d"),
    execution_version: RelayAdapt7702ExecutionVersionKind::CurrentNonceAware,
    evidence_class: RelayAdapt7702EvidenceClass::FrozenPackageConfigurationAssertion,
    provenance: PACKAGE_PROVENANCE,
};

const POLYGON_CURRENT: RelayAdapt7702CurrentMetadata = BNB_CURRENT;
const ARBITRUM_CURRENT: RelayAdapt7702CurrentMetadata = BNB_CURRENT;

const ETHEREUM_REGISTRY: RelayAdapt7702AdvisoryRegistryMetadata =
    RelayAdapt7702AdvisoryRegistryMetadata {
        address: address!("0x6FA84Bc1587CC90978dC9535d4d38DC74fa4b522"),
        evidence_class: RelayAdapt7702EvidenceClass::FrozenPackageConfigurationAssertion,
        provenance: REGISTRY_PROVENANCE,
    };

const BNB_REGISTRY: RelayAdapt7702AdvisoryRegistryMetadata =
    RelayAdapt7702AdvisoryRegistryMetadata {
        address: address!("0xD2014c99566d9e932e3Cfa7aCe840FC570e0fD5f"),
        evidence_class: RelayAdapt7702EvidenceClass::FrozenPackageConfigurationAssertion,
        provenance: REGISTRY_PROVENANCE,
    };

const POLYGON_REGISTRY: RelayAdapt7702AdvisoryRegistryMetadata = BNB_REGISTRY;
const ARBITRUM_REGISTRY: RelayAdapt7702AdvisoryRegistryMetadata = BNB_REGISTRY;

const ETHEREUM_HISTORY: [RelayAdapt7702HistoricalMetadata; 1] =
    [RelayAdapt7702HistoricalMetadata {
        address: address!("0x2df3d82c06339387a4532c685daaf39a218cf56e"),
        construction_version: None,
        evidence_class: RelayAdapt7702EvidenceClass::HistoricalAddressObservation,
        provenance: HISTORICAL_PROVENANCE,
    }];

const BNB_HISTORY: [RelayAdapt7702HistoricalMetadata; 1] = [RelayAdapt7702HistoricalMetadata {
    address: address!("0x6fa84bc1587cc90978dc9535d4d38dc74fa4b522"),
    construction_version: None,
    evidence_class: RelayAdapt7702EvidenceClass::HistoricalAddressObservation,
    provenance: HISTORICAL_PROVENANCE,
}];

const POLYGON_HISTORY: [RelayAdapt7702HistoricalMetadata; 1] = BNB_HISTORY;
const ARBITRUM_HISTORY: [RelayAdapt7702HistoricalMetadata; 1] = BNB_HISTORY;

static ETHEREUM_METADATA: RelayAdapt7702ChainMetadata = RelayAdapt7702ChainMetadata {
    chain_id: 1,
    current: ETHEREUM_CURRENT,
    advisory_registry: ETHEREUM_REGISTRY,
    known_history: &ETHEREUM_HISTORY,
};

static BNB_METADATA: RelayAdapt7702ChainMetadata = RelayAdapt7702ChainMetadata {
    chain_id: 56,
    current: BNB_CURRENT,
    advisory_registry: BNB_REGISTRY,
    known_history: &BNB_HISTORY,
};

static POLYGON_METADATA: RelayAdapt7702ChainMetadata = RelayAdapt7702ChainMetadata {
    chain_id: 137,
    current: POLYGON_CURRENT,
    advisory_registry: POLYGON_REGISTRY,
    known_history: &POLYGON_HISTORY,
};

static ARBITRUM_METADATA: RelayAdapt7702ChainMetadata = RelayAdapt7702ChainMetadata {
    chain_id: 42161,
    current: ARBITRUM_CURRENT,
    advisory_registry: ARBITRUM_REGISTRY,
    known_history: &ARBITRUM_HISTORY,
};

/// Return static metadata for a supported chain.
#[must_use]
pub fn relay_adapt_7702_metadata(chain_id: u64) -> Option<&'static RelayAdapt7702ChainMetadata> {
    match chain_id {
        1 => Some(&ETHEREUM_METADATA),
        56 => Some(&BNB_METADATA),
        137 => Some(&POLYGON_METADATA),
        42161 => Some(&ARBITRUM_METADATA),
        _ => None,
    }
}

/// Return the current package-configured address and version for a chain.
#[must_use]
pub fn current_relay_adapt_7702(chain_id: u64) -> Option<RelayAdapt7702CurrentMetadata> {
    relay_adapt_7702_metadata(chain_id).map(|metadata| metadata.current())
}

/// Return the advisory registry address for a chain.
#[must_use]
pub fn advisory_relay_adapt_7702_registry(
    chain_id: u64,
) -> Option<RelayAdapt7702AdvisoryRegistryMetadata> {
    relay_adapt_7702_metadata(chain_id).map(|metadata| metadata.advisory_registry())
}

/// Return known historical addresses without assigning versions from their order.
#[must_use]
pub fn known_relay_adapt_7702_history(
    chain_id: u64,
) -> Option<&'static [RelayAdapt7702HistoricalMetadata]> {
    relay_adapt_7702_metadata(chain_id).map(|metadata| metadata.known_history())
}

/// Return address metadata without making a network request.
#[must_use]
pub fn relay_adapt_7702_address_metadata(
    chain_id: u64,
    address: Address,
) -> Option<RelayAdapt7702AddressMetadata> {
    relay_adapt_7702_metadata(chain_id).and_then(|metadata| metadata.address_metadata(address))
}

/// Resolve construction metadata for a configured address without replacing it.
///
/// An explicitly supplied version remains authoritative, including for an
/// address not present in the static records. Without one, only the reviewed
/// current address can be constructed; historical and unknown addresses fail
/// closed because their ABI version is unproven.
#[must_use]
pub fn resolve_relay_adapt_7702_metadata(
    chain_id: u64,
    configured_address: Address,
    configured_version: Option<RelayAdapt7702ExecutionVersionKind>,
) -> Option<RelayAdapt7702AddressMetadata> {
    if let Some(version) = configured_version {
        return Some(RelayAdapt7702AddressMetadata {
            address: configured_address,
            construction_version: Some(version),
            evidence_class: RelayAdapt7702EvidenceClass::ExplicitConfiguration,
            provenance: EXPLICIT_PROVENANCE,
        });
    }

    relay_adapt_7702_address_metadata(chain_id, configured_address)
        .filter(|metadata| metadata.construction_version.is_some())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, address};

    use super::{
        RelayAdapt7702EvidenceClass, RelayAdapt7702ExecutionVersionKind,
        advisory_relay_adapt_7702_registry, current_relay_adapt_7702,
        known_relay_adapt_7702_history, relay_adapt_7702_address_metadata,
        resolve_relay_adapt_7702_metadata,
    };
    use crate::types::ChainConfigDefaults;

    #[test]
    fn four_chain_defaults_use_reviewed_current_relay_adapt_7702_addresses() {
        let expected = [
            (1, address!("0x05aE73C5925d843864AE6f261f3175dE2ebCd963")),
            (56, address!("0x48cf4b897f64D81212c1423D78a05E828d0cE19d")),
            (137, address!("0x48cf4b897f64D81212c1423D78a05E828d0cE19d")),
            (
                42161,
                address!("0x48cf4b897f64D81212c1423D78a05E828d0cE19d"),
            ),
        ];

        for (chain_id, address) in expected {
            assert_eq!(
                ChainConfigDefaults::for_chain(chain_id)
                    .expect("supported chain defaults")
                    .relay_adapt_7702_contract,
                address
            );
        }
    }

    #[test]
    fn current_metadata_is_nonce_aware_without_an_execution_nonce() {
        for chain_id in [1, 56, 137, 42161] {
            let current = current_relay_adapt_7702(chain_id).expect("current metadata");
            assert_eq!(
                current.execution_version,
                RelayAdapt7702ExecutionVersionKind::CurrentNonceAware
            );
            assert_eq!(
                current.evidence_class,
                RelayAdapt7702EvidenceClass::FrozenPackageConfigurationAssertion
            );
            assert!(current.provenance.limitations.contains("bytecode"));
            assert!(current.provenance.limitations.contains("source safety"));
        }
    }

    #[test]
    fn advisory_registry_addresses_match_reviewed_package_configuration() {
        assert_eq!(
            advisory_relay_adapt_7702_registry(1)
                .expect("Ethereum registry")
                .address,
            address!("0x6FA84Bc1587CC90978dC9535d4d38DC74fa4b522")
        );
        for chain_id in [56, 137, 42161] {
            assert_eq!(
                advisory_relay_adapt_7702_registry(chain_id)
                    .expect("non-Ethereum registry")
                    .address,
                address!("0xD2014c99566d9e932e3Cfa7aCe840FC570e0fD5f")
            );
        }
    }

    #[test]
    fn history_order_does_not_infer_execution_version() {
        for chain_id in [1, 56, 137, 42161] {
            let history = known_relay_adapt_7702_history(chain_id).expect("history");
            assert!(!history.is_empty());
            for entry in history {
                assert_eq!(entry.construction_version, None);
                assert_eq!(
                    relay_adapt_7702_address_metadata(chain_id, entry.address)
                        .expect("known history address")
                        .construction_version(),
                    None
                );
            }
        }
    }

    #[test]
    fn configured_target_and_explicit_version_remain_authoritative() {
        let configured_address = known_relay_adapt_7702_history(1)
            .expect("history")
            .first()
            .expect("historical address")
            .address;
        let metadata = resolve_relay_adapt_7702_metadata(
            1,
            configured_address,
            Some(RelayAdapt7702ExecutionVersionKind::LegacyPreExecuteNonce),
        )
        .expect("explicit configured version");

        assert_eq!(metadata.address, configured_address);
        assert_eq!(
            metadata.construction_version(),
            Some(RelayAdapt7702ExecutionVersionKind::LegacyPreExecuteNonce)
        );
        assert_eq!(
            metadata.evidence_class,
            RelayAdapt7702EvidenceClass::ExplicitConfiguration
        );
        assert_ne!(
            metadata.address,
            advisory_relay_adapt_7702_registry(1)
                .expect("registry metadata")
                .address
        );
    }

    #[test]
    fn unknown_or_unproven_addresses_fail_closed_for_construction() {
        let unknown = Address::from([0x99; 20]);
        assert_eq!(resolve_relay_adapt_7702_metadata(1, unknown, None), None);

        let historical = known_relay_adapt_7702_history(1)
            .expect("history")
            .first()
            .expect("historical address")
            .address;
        assert_eq!(resolve_relay_adapt_7702_metadata(1, historical, None), None);
    }

    #[test]
    fn explicit_current_and_legacy_metadata_are_retained() {
        let cases = [
            (
                current_relay_adapt_7702(1)
                    .expect("current metadata")
                    .address,
                RelayAdapt7702ExecutionVersionKind::LegacyPreExecuteNonce,
            ),
            (
                known_relay_adapt_7702_history(1)
                    .expect("history")
                    .first()
                    .expect("historical address")
                    .address,
                RelayAdapt7702ExecutionVersionKind::CurrentNonceAware,
            ),
        ];
        for (address, version) in cases {
            let metadata = resolve_relay_adapt_7702_metadata(1, address, Some(version))
                .expect("explicit execution version");
            assert_eq!(metadata.address, address);
            assert_eq!(metadata.construction_version(), Some(version));
        }
    }
}
