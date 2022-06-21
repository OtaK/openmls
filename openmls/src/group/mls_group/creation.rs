use crate::{
    group::{
        core_group::create_commit_params::CreateCommitParams,
        errors::{CoreGroupBuildError, ExternalCommitError, WelcomeError},
    },
    messages::public_group_state::VerifiablePublicGroupState,
};

use super::*;

impl MlsGroup {
    fn new_with_kpb(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        group_id: GroupId,
        kpb: KeyPackageBundle,
    ) -> Result<Self, NewGroupError> {
        let group_config = CoreGroupConfig {
            add_ratchet_tree_extension: mls_group_config.use_ratchet_tree_extension,
        };
        let group = CoreGroup::builder(group_id, key_package_bundle)
            .with_config(group_config)
            .with_required_capabilities(mls_group_config.required_capabilities.clone())
            .with_max_past_epoch_secrets(mls_group_config.max_past_epochs)
            .build(backend)
            .map_err(|e| match e {
                CoreGroupBuildError::LibraryError(e) => e.into(),
                CoreGroupBuildError::UnsupportedProposalType => {
                    NewGroupError::UnsupportedProposalType
                }
                CoreGroupBuildError::UnsupportedExtensionType => {
                    NewGroupError::UnsupportedExtensionType
                }
                // We don't support PSKs yet
                CoreGroupBuildError::PskError(e) => {
                    log::debug!("Unexpected PSK error: {:?}", e);
                    LibraryError::custom("Unexpected PSK error").into()
                }
            })?;

        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::Operational,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }

    fn new_with_welcome(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, NewGroupError> {
        // TODO #751
        let mut group =
            CoreGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle, backend)?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::Operational,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }
}

#[cfg(not(feature = "async"))]
impl MlsGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member. This
    /// function removes the `KeyPackageBundle` corresponding to the
    /// `key_package_hash` from the key store. Returns an error
    /// ([`NewGroupError::NoMatchingKeyPackageBundle`]) if no
    /// [`KeyPackageBundle`] can be found.
    pub fn new(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        group_id: GroupId,
        key_package_hash: &[u8],
    ) -> Result<Self, NewGroupError> {
        // TODO #751
        let key_package_bundle: KeyPackageBundle = backend
            .key_store()
            .read(key_package_hash)
            .ok_or(NewGroupError::NoMatchingKeyPackageBundle)?;
        backend
            .key_store()
            .delete(key_package_hash)
            .map_err(|_| NewGroupError::KeyStoreDeletionError)?;

        Self::new_with_kpb(backend, mls_group_config, group_id, key_package_bundle)
    }

    /// Creates a new group from a [`Welcome`] message. Returns an error
    /// ([`WelcomeError::NoMatchingKeyPackageBundle`]) if no
    /// [`KeyPackageBundle`] can be found.
    pub fn new_from_welcome(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<Self, WelcomeError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);
        let (key_package_bundle, hash_ref) = welcome
            .secrets()
            .iter()
            .find_map(|egs| {
                let hash_ref = egs.new_member().as_slice().to_vec();
                backend
                    .key_store()
                    .read(&hash_ref)
                    .map(|kpb: KeyPackageBundle| (kpb, hash_ref))
            })
            .ok_or(WelcomeError::NoMatchingKeyPackageBundle)?;

        // Delete the KeyPackageBundle from the key store
        backend
            .key_store()
            .delete(&hash_ref)
            .map_err(|_| WelcomeError::KeyStoreDeletionError)?;

        Self::new_with_welcome(
            backend,
            mls_group_config,
            welcome,
            ratchet_tree,
            key_package_bundle,
        )
    }

    /// Join an existing group through an External Commit.
    /// The resulting [`MlsGroup`] instance starts off with a pending
    /// commit (the external commit, which adds this client to the group).
    /// Merging this commit is necessary for this [`MlsGroup`] instance to
    /// function properly, as, for example, this client is not yet part of the
    /// tree. As a result, it is not possible to clear the pending commit. If
    /// the external commit was rejected due to an epoch change, the
    /// [`MlsGroup`] instance has to be discarded and a new one has to be
    /// created using this function based on the latest `ratchet_tree` and
    /// public group state. For more information on the external init process,
    /// please see Section 11.2.1 in the MLS specification.
    pub fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        tree_option: Option<&[Option<Node>]>,
        verifiable_public_group_state: VerifiablePublicGroupState,
        mls_group_config: &MlsGroupConfig,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
    ) -> Result<(Self, MlsMessageOut), ExternalCommitError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);

        // Prepare the commit parameters
        let framing_parameters =
            FramingParameters::new(aad, mls_group_config.wire_format_policy().outgoing());

        let proposal_store = ProposalStore::new();
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(credential_bundle)
            .proposal_store(&proposal_store)
            .build();
        let (mut group, create_commit_result) = CoreGroup::join_by_external_commit(
            backend,
            params,
            tree_option,
            verifiable_public_group_state,
        )?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::PendingCommit(Box::new(PendingCommitState::External(
                create_commit_result.staged_commit,
            ))),
            state_changed: InnerState::Changed,
        };

        Ok((mls_group, create_commit_result.commit.into()))
    }
}

#[cfg(feature = "async")]
impl MlsGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member. This
    /// function removes the `KeyPackageBundle` corresponding to the
    /// `key_package_hash` from the key store. Returns an error
    /// ([`NewGroupError::NoMatchingKeyPackageBundle`]) if no
    /// [`KeyPackageBundle`] can be found.
    pub async fn new(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        group_id: GroupId,
        key_package_hash: &[u8],
    ) -> Result<Self, NewGroupError> {
        // TODO #751
        let key_package_bundle: KeyPackageBundle = backend
            .key_store()
            .read(key_package_hash)
            .await
            .ok_or(NewGroupError::NoMatchingKeyPackageBundle)?;
        backend
            .key_store()
            .delete(key_package_hash)
            .await
            .map_err(|_| NewGroupError::KeyStoreDeletionError)?;

        Self::new_with_kpb(backend, mls_group_config, group_id, key_package_bundle)
    }

    /// Creates a new group from a [`Welcome`] message. Returns an error
    /// ([`WelcomeError::NoMatchingKeyPackageBundle`]) if no
    /// [`KeyPackageBundle`] can be found.
    pub async fn new_from_welcome(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<Self, WelcomeError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);
        let mut kpb_info = None;
        for egs in welcome.secrets().iter() {
            let hash_ref_raw = egs.new_member().as_slice();
            if let Some(kpb) = backend.key_store().read(hash_ref_raw).await {
                kpb_info = Some((kpb, hash_ref_raw.to_vec()));
                break;
            }
        }
        let (key_package_bundle, hash_ref) = if let Some(kpb_info) = kpb_info.take() {
            kpb_info
        } else {
            return Err(WelcomeError::NoMatchingKeyPackageBundle);
        };

        // Delete the KeyPackageBundle from the key store
        backend
            .key_store()
            .delete(&hash_ref)
            .await
            .map_err(|_| WelcomeError::KeyStoreDeletionError)?;

        Self::new_with_welcome(
            backend,
            mls_group_config,
            welcome,
            ratchet_tree,
            key_package_bundle,
        )
    }

    /// Join an existing group through an External Commit.
    /// The resulting [`MlsGroup`] instance starts off with a pending
    /// commit (the external commit, which adds this client to the group).
    /// Merging this commit is necessary for this [`MlsGroup`] instance to
    /// function properly, as, for example, this client is not yet part of the
    /// tree. As a result, it is not possible to clear the pending commit. If
    /// the external commit was rejected due to an epoch change, the
    /// [`MlsGroup`] instance has to be discarded and a new one has to be
    /// created using this function based on the latest `ratchet_tree` and
    /// public group state. For more information on the external init process,
    /// please see Section 11.2.1 in the MLS specification.
    pub fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        tree_option: Option<&[Option<Node>]>,
        verifiable_public_group_state: VerifiablePublicGroupState,
        mls_group_config: &MlsGroupConfig,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
    ) -> Result<(Self, MlsMessageOut), ExternalCommitError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);

        // Prepare the commit parameters
        let framing_parameters =
            FramingParameters::new(aad, mls_group_config.wire_format_policy().outgoing());

        let proposal_store = ProposalStore::new();
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(credential_bundle)
            .proposal_store(&proposal_store)
            .build();
        let (mut group, create_commit_result) = CoreGroup::join_by_external_commit(
            backend,
            params,
            tree_option,
            verifiable_public_group_state,
        )?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::PendingCommit(Box::new(PendingCommitState::External(
                create_commit_result.staged_commit,
            ))),
            state_changed: InnerState::Changed,
        };

        Ok((mls_group, create_commit_result.commit.into()))
    }
}
