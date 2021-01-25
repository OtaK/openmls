use crate::ciphersuite::*;
use crate::codec::*;
use crate::config::Config;
use crate::credentials::*;
use crate::key_packages::*;
use crate::messages::proposals::*;

// Tree modules
pub(crate) mod binary_tree;
mod blanked_tree;
pub(crate) mod codec;
pub(crate) mod errors;
pub(crate) mod hash_input;
pub mod index;
pub mod node;
pub(crate) mod path_keys;
pub(crate) mod private_tree;
pub(crate) mod secret_tree;
pub(crate) mod sender_ratchet;
pub(crate) mod treemath;

pub(crate) use errors::*;
use hash_input::*;
use index::*;
use node::*;
use private_tree::{PathSecrets, PrivateTree};
pub use secret_tree::SecretTypeError;

use self::blanked_tree::*;
use self::private_tree::CommitSecret;
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

use std::collections::HashSet;
use std::iter::FromIterator;

// Internal tree tests
#[cfg(test)]
mod test_path_keys;
#[cfg(test)]
mod test_private_tree;
#[cfg(test)]
mod test_resolution;
#[cfg(test)]
mod test_secret_tree;
#[cfg(test)]
mod test_treemath;
#[cfg(test)]
mod test_util;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
/// The ratchet tree.
pub struct RatchetTree {
    /// The ciphersuite used in this tree.
    ciphersuite: &'static Ciphersuite,

    /// All nodes in the tree.
    /// Note that these only hold public values.
    /// Private values are stored in the `private_tree`.
    pub public_tree: BlankedTree<Node>,

    /// This holds all private values in the tree.
    /// See `PrivateTree` for details.
    private_tree: PrivateTree,
}

implement_persistence!(RatchetTree, public_tree, private_tree);

impl RatchetTree {
    /// Create a new empty `RatchetTree`.
    pub(crate) fn new(ciphersuite: &'static Ciphersuite, kpb: KeyPackageBundle) -> RatchetTree {
        let nodes = vec![Some(Node::Leaf(kpb.key_package().clone()))];
        let private_tree = PrivateTree::from_key_package_bundle(NodeIndex::from(0u32), &kpb);
        let public_tree = BlankedTree::from(nodes);

        RatchetTree {
            ciphersuite,
            public_tree,
            private_tree,
        }
    }

    /// Create a new `RatchetTree` by cloning the public tree nodes from another
    /// tree and an empty `PrivateTree`
    pub(crate) fn new_from_public_tree(ratchet_tree: &RatchetTree) -> Self {
        RatchetTree {
            ciphersuite: ratchet_tree.ciphersuite,
            public_tree: ratchet_tree.public_tree.clone(),
            private_tree: PrivateTree::new(ratchet_tree.private_tree.node_index()),
        }
    }

    /// Generate a new `RatchetTree` from `Node`s with the client's key package
    /// bundle `kpb`.
    pub(crate) fn new_from_nodes(
        ciphersuite: &'static Ciphersuite,
        kpb: KeyPackageBundle,
        node_options: &[Option<Node>],
    ) -> Result<RatchetTree, TreeError> {
        fn find_kp_in_tree(
            key_package: &KeyPackage,
            nodes: &[Option<Node>],
        ) -> Result<NodeIndex, TreeError> {
            for (i, node_option) in nodes.iter().enumerate() {
                if let Some(node) = node_option {
                    if let Node::Leaf(kp) = &node {
                        if kp == key_package {
                            return Ok(NodeIndex::from(i));
                        }
                    }
                }
            }
            Err(TreeError::InvalidArguments)
        }

        // Find the own node in the list of nodes.
        let own_node_index = find_kp_in_tree(kpb.key_package(), node_options)?;

        // Create a blanked tree from the input nodes.
        let public_tree = BlankedTree::from(node_options.to_vec());

        // Build private tree
        let private_tree = PrivateTree::from_key_package_bundle(own_node_index, &kpb);

        // Build tree.
        Ok(RatchetTree {
            ciphersuite,
            public_tree,
            private_tree,
        })
    }

    /// Return a mutable reference to the `PrivateTree`.
    pub(crate) fn private_tree_mut(&mut self) -> &mut PrivateTree {
        &mut self.private_tree
    }

    /// Return a reference to the `PrivateTree`.
    pub(crate) fn private_tree(&self) -> &PrivateTree {
        &self.private_tree
    }

    fn tree_size(&self) -> NodeIndex {
        NodeIndex::from(self.public_tree.size())
    }

    /// Get a vector with all nodes in the tree, containing `None` for blank
    /// nodes.
    pub fn public_key_tree(&self) -> &Vec<Option<Node>> {
        self.public_tree.nodes()
    }

    /// Get a vector with a copy of all nodes in the tree, containing `None` for
    /// blank nodes.
    pub fn public_key_tree_copy(&self) -> Vec<Option<Node>> {
        self.public_key_tree().clone()
    }

    pub fn leaf_count(&self) -> LeafIndex {
        self.tree_size().into()
    }

    fn resolve(
        &self,
        index: NodeIndex,
        exclusion_list: &HashSet<&NodeIndex>,
    ) -> Result<Vec<NodeIndex>, TreeError> {
        let predicate = |i, node: &Node| match node {
            Node::Leaf(_) => {
                if exclusion_list.contains(&i) {
                    vec![]
                } else {
                    vec![i]
                }
            }
            Node::Parent(parent_node) => {
                let mut unmerged_leaves: Vec<NodeIndex> = vec![i];
                unmerged_leaves.extend(
                    parent_node
                        .unmerged_leaves()
                        .iter()
                        .map(|n| NodeIndex::from(*n)),
                );
                unmerged_leaves
            }
        };
        Ok(self.public_tree.resolve(&index, &predicate)?)
    }

    /// Get the index of the own node.
    pub(crate) fn own_node_index(&self) -> NodeIndex {
        self.private_tree.node_index()
    }

    /// Get a reference to the own key package.
    pub fn own_key_package(&self) -> &KeyPackage {
        // We can unwrap here, because our own index should always be within the
        // tree.
        let own_node_option = &self.public_tree.node(&self.own_node_index()).unwrap();
        // We can unwrap here, because our own leaf can't be blank.
        let own_node = own_node_option.as_ref().unwrap();
        // We can unwrap here, because we know the leaf node is indeed a `Leaf`.
        own_node.as_leaf_node().unwrap()
    }

    /// Get a mutable reference to the own key package.
    fn own_key_package_mut(&mut self) -> &mut KeyPackage {
        // We can unwrap here, because our own index should always be within the
        // tree.
        let own_node_option = self.public_tree.node_mut(&self.own_node_index()).unwrap();
        // We can unwrap here, because our own leaf can't be blank.
        let own_node = own_node_option.as_mut().unwrap();
        // We can unwrap here, because we know the leaf node is indeed a `Leaf`.
        own_node.as_leaf_node_mut().unwrap()
    }

    /// 7.7. Update Paths
    ///
    /// Update the path for incoming commits.
    ///
    /// > The path contains a public key and encrypted secret value for all
    /// > intermediate nodes in the path above the leaf. The path is ordered
    /// > from the closest node to the leaf to the root; each node MUST be the
    /// > parent of its predecessor.
    pub(crate) fn update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &UpdatePath,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&NodeIndex>,
    ) -> Result<&CommitSecret, TreeError> {
        let own_index = self.own_node_index();
        // Make `sender` a node index, making it easier to handle.
        let sender = NodeIndex::from(sender);

        // Find common ancestor of own leaf and sender leaf
        let common_ancestor_index = self.public_tree.common_ancestor(sender, own_index)?;

        // Calculate sender direct path & co-path, common path
        let sender_direct_path = self.public_tree.direct_path_root(sender)?;
        let sender_co_path = self.public_tree.copath(sender)?;

        // Find the position of the common ancestor in the sender's direct path
        let common_ancestor_sender_dirpath_index = &sender_direct_path
            .iter()
            .position(|&x| x == common_ancestor_index)
            .unwrap();
        let common_ancestor_copath_index =
            match sender_co_path.get(*common_ancestor_sender_dirpath_index) {
                Some(i) => *i,
                None => return Err(TreeError::InvalidArguments),
            };

        // Resolve the node of that co-path index
        let resolution = self.resolve(common_ancestor_copath_index, &new_leaves_indexes)?;
        let position_in_resolution = resolution.iter().position(|&x| x == own_index).unwrap_or(0);

        // Decrypt the ciphertext of that node
        let common_ancestor_node =
            match update_path.nodes.get(*common_ancestor_sender_dirpath_index) {
                Some(node) => node,
                None => return Err(TreeError::InvalidArguments),
            };
        debug_assert_eq!(
            resolution.len(),
            common_ancestor_node.encrypted_path_secret.len()
        );
        if resolution.len() != common_ancestor_node.encrypted_path_secret.len() {
            return Err(TreeError::InvalidUpdatePath);
        }
        let hpke_ciphertext = &common_ancestor_node.encrypted_path_secret[position_in_resolution];

        // Get the HPKE private key.
        // It's either the own key or must be in the path of the private tree.
        let private_key = if resolution[position_in_resolution] == own_index {
            self.private_tree.hpke_private_key()
        } else {
            match self
                .private_tree
                .path_keys()
                .get(common_ancestor_copath_index)
            {
                Some(k) => k,
                None => return Err(TreeError::InvalidArguments),
            }
        };

        // Compute the common path between the common ancestor and the root
        let common_path = self.public_tree.direct_path(common_ancestor_index)?;

        debug_assert!(
            sender_direct_path.len() >= common_path.len(),
            "Library error. Direct path cannot be shorter than common path."
        );

        // Decrypt the secret and derive path secrets
        let secret = Secret::from(self.ciphersuite.hpke_open(
            hpke_ciphertext,
            &private_key,
            group_context,
            &[],
        )?);
        // Derive new path secrets and generate keypairs
        let new_path_public_keys =
            self.private_tree
                .continue_path_secrets(&self.ciphersuite, secret, &common_path);

        // Extract public keys from UpdatePath
        let update_path_public_keys: Vec<HPKEPublicKey> = update_path
            .nodes
            .iter()
            .map(|node| node.public_key.clone())
            .collect();

        // Check that the public keys are consistent with the update path.
        let (_, common_public_keys) =
            update_path_public_keys.split_at(update_path_public_keys.len() - common_path.len());

        if new_path_public_keys != common_public_keys {
            return Err(TreeError::InvalidUpdatePath);
        }

        // Merge new nodes into the tree
        self.merge_direct_path_keys(update_path, sender_direct_path)?;
        self.merge_public_keys(&new_path_public_keys, &common_path)?;
        self.public_tree.replace(
            &NodeIndex::from(sender),
            Some(Node::Leaf(update_path.leaf_key_package.clone())),
        )?;
        self.compute_parent_hash(NodeIndex::from(sender))?;

        // TODO: Do we really want to return the commit secret here?
        Ok(self.private_tree.commit_secret())
    }

    /// Update the private tree with the new `KeyPackageBundle`.
    pub(crate) fn replace_private_tree(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
    ) -> &CommitSecret {
        let _path_option = self.replace_private_tree_(
            key_package_bundle,
            group_context,
            None, /* without update path */
        );
        self.private_tree.commit_secret()
    }

    /// Update the private tree.
    pub(crate) fn refresh_private_tree(
        &mut self,
        credential_bundle: &CredentialBundle,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&NodeIndex>,
    ) -> (&CommitSecret, UpdatePath, PathSecrets, KeyPackageBundle) {
        // Generate new keypair
        let own_index = self.own_node_index();

        // Replace the init key in the current KeyPackage
        let mut key_package_bundle =
            KeyPackageBundle::from_rekeyed_key_package(self.own_key_package());

        // Replace the private tree with a new one based on the new key package
        // bundle and store the key package in the own node.
        let mut path = self
            .replace_private_tree_(
                &key_package_bundle,
                group_context,
                Some(new_leaves_indexes), /* with update path */
            )
            .unwrap();

        // Compute the parent hash extension and update the KeyPackage and sign
        // it. We can unwrap here, because own_index is within the tree.
        let parent_hash = self.compute_parent_hash(own_index).unwrap();
        let key_package = self.own_key_package_mut();
        key_package.update_parent_hash(&parent_hash);
        // Sign the KeyPackage
        key_package.sign(credential_bundle);
        // Store it in the UpdatePath
        path.leaf_key_package = key_package.clone();
        // Update it in the KeyPackageBundle
        key_package_bundle.set_key_package(key_package.clone());

        (
            self.private_tree.commit_secret(),
            path,
            self.private_tree.path_secrets().to_vec(),
            key_package_bundle,
        )
    }

    /// Replace the private tree with a new one based on the
    /// `key_package_bundle`.
    fn replace_private_tree_(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
        new_leaves_indexes_option: Option<HashSet<&NodeIndex>>,
    ) -> Option<UpdatePath> {
        let key_package = key_package_bundle.key_package().clone();
        let ciphersuite = key_package.ciphersuite();
        // Compute the direct path and keypairs along it
        let own_index = self.own_node_index();
        // We can unwrap here, because we know that `own_index` is within the
        // tree.
        let direct_path_root = self.public_tree.direct_path_root(own_index).unwrap();
        // Update private tree and merge corresponding public keys.
        let (private_tree, new_public_keys) = PrivateTree::new_with_keys(
            ciphersuite,
            own_index,
            key_package_bundle,
            &direct_path_root,
        );
        self.private_tree = private_tree;

        self.merge_public_keys(&new_public_keys, &direct_path_root)
            .unwrap();

        // Update own leaf node with the new values
        // We can unwrap here two times, because own_index is within the tree.
        self.public_tree
            .replace(&own_index, Some(Node::Leaf(key_package.clone())))
            .unwrap();
        self.compute_parent_hash(self.own_node_index()).unwrap();
        if let Some(new_leaves_indexes) = new_leaves_indexes_option {
            let update_path_nodes = self
                .encrypt_to_copath(new_public_keys, group_context, new_leaves_indexes)
                .unwrap();
            let update_path = UpdatePath::new(key_package, update_path_nodes);
            Some(update_path)
        } else {
            None
        }
    }

    /// Encrypt the path secrets to the co path and return the update path.
    fn encrypt_to_copath(
        &self,
        public_keys: Vec<HPKEPublicKey>,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&NodeIndex>,
    ) -> Result<Vec<UpdatePathNode>, TreeError> {
        let copath = treemath::copath(self.private_tree.node_index(), self.leaf_count())
            .expect("encrypt_to_copath: Error when computing copath.");
        // Return if the length of the copath is zero
        if copath.is_empty() {
            return Ok(vec![]);
        }
        let path_secrets = self.private_tree.path_secrets();

        debug_assert_eq!(path_secrets.len(), copath.len());
        if path_secrets.len() != copath.len() {
            return Err(TreeError::InvalidArguments);
        }
        debug_assert_eq!(public_keys.len(), copath.len());
        if public_keys.len() != copath.len() {
            return Err(TreeError::InvalidArguments);
        }

        let mut direct_path_nodes = vec![];
        let mut ciphertexts = vec![];
        for (path_secret, copath_node) in path_secrets.iter().zip(copath.iter()) {
            let node_ciphertexts: Vec<HpkeCiphertext> = self
                .resolve(*copath_node, &new_leaves_indexes)?
                .iter()
                .map(|&index| {
                    let node = self
                        .public_tree
                        .node(&index)
                        // We can unwrap here, because all nodes of a resolution are
                        // within the tree.
                        .unwrap()
                        .as_ref()
                        // We can unwrap again, because we know that the
                        // resolution only points to non-blank nodes.
                        .unwrap();
                    let pk = node.public_key();
                    self.ciphersuite
                        .hpke_seal_secret(&pk, group_context, &[], &path_secret)
                })
                .collect();
            // TODO Check that all public keys are non-empty
            // TODO Handle potential errors
            ciphertexts.push(node_ciphertexts);
        }
        for (public_key, node_ciphertexts) in public_keys.iter().zip(ciphertexts.iter()) {
            direct_path_nodes.push(UpdatePathNode {
                // TODO: don't clone ...
                public_key: public_key.clone(),
                encrypted_path_secret: node_ciphertexts.clone(),
            });
        }
        Ok(direct_path_nodes)
    }

    /// Merge public keys from a direct path to this tree along the given path.
    fn merge_direct_path_keys(
        &mut self,
        direct_path: &UpdatePath,
        path: Vec<NodeIndex>,
    ) -> Result<(), TreeError> {
        debug_assert_eq!(direct_path.nodes.len(), path.len());
        if direct_path.nodes.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }

        for (i, p) in path.iter().enumerate() {
            let public_key = direct_path.nodes[i].clone().public_key;
            let node = ParentNode::new(public_key.clone(), &[], &[]);
            self.public_tree.replace(p, Some(Node::Parent(node)))?;
        }

        Ok(())
    }

    /// Validates that the `public_keys` matches the public keys in the tree
    /// along `path`
    pub(crate) fn validate_public_keys(
        &self,
        public_keys: &[HPKEPublicKey],
        path: &[NodeIndex],
    ) -> Result<(), TreeError> {
        if public_keys.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }
        for (public_key, node_index) in public_keys.iter().zip(path) {
            if let Some(node) = &self.public_tree.node(node_index)? {
                if node.public_key() != public_key {
                    return Err(TreeError::InvalidArguments);
                }
            } else {
                return Err(TreeError::InvalidArguments);
            }
        }
        Ok(())
    }

    /// Merges `public_keys` into the tree along the `path`
    pub(crate) fn merge_public_keys(
        &mut self,
        public_keys: &[HPKEPublicKey],
        path: &[NodeIndex],
    ) -> Result<(), TreeError> {
        debug_assert_eq!(public_keys.len(), path.len());
        if public_keys.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }
        for i in 0..path.len() {
            // TODO: drop clone
            let node = ParentNode::new(public_keys[i].clone(), &[], &[]);
            self.public_tree
                .replace(&path[i], Some(Node::Parent(node)))?;
        }
        Ok(())
    }

    /// Add nodes for the provided key packages.
    pub(crate) fn add_nodes(&mut self, new_kps: &[&KeyPackage]) -> Vec<(NodeIndex, Credential)> {
        // Create leaf nodes from the given KeyPackages.
        let new_nodes = new_kps.iter().map(|&kp| Node::Leaf(kp.clone())).collect();

        // Add the leaves to the tree.
        let new_indices = self.public_tree.add_blanked(new_nodes);

        // Compile a list of the new indices and their credentials.
        let new_indices_and_credentials = new_indices
            .iter()
            .map(|index| {
                (
                    index.clone(),
                    self.public_tree
                        .node(index)
                        // We can unwrap here, because we know that the indices of
                        // new nodes are within the tree.
                        .unwrap()
                        .as_ref()
                        // We can unwrap again, because we know the new leaves are
                        // not blank.
                        .unwrap()
                        .as_leaf_node()
                        // We can unwrap here, because we know the indices only point to
                        // leaves.
                        .unwrap()
                        .credential()
                        .clone(),
                )
            })
            .collect();

        new_indices_and_credentials
    }

    /// Applies a list of proposals from a Commit to the tree.
    /// `proposal_queue` is the queue of proposals received or sent in the
    /// current epoch `updates_key_package_bundles` is the list of own
    /// KeyPackageBundles corresponding to updates or commits sent in the
    /// current epoch
    pub fn apply_proposals(
        &mut self,
        proposal_queue: ProposalQueue,
        updates_key_package_bundles: &[KeyPackageBundle],
    ) -> Result<ApplyProposalsValues, TreeError> {
        let mut has_updates = false;
        let mut has_removes = false;

        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            has_updates = true;
            let update_proposal = &queued_proposal.proposal().as_update().unwrap();
            let sender_index = queued_proposal.sender().to_node_index();
            // Blank the direct path of that leaf node
            self.public_tree.blank_direct_path(&sender_index)?;
            // Prepare leaf node
            let leaf_node = Some(Node::Leaf(update_proposal.key_package.clone()));
            // Replace the leaf node
            self.public_tree.replace(&sender_index, leaf_node)?;
            // Check if it is a self-update
            if sender_index == self.own_node_index() {
                let own_kpb = match updates_key_package_bundles
                    .iter()
                    .find(|kpb| kpb.key_package() == &update_proposal.key_package)
                {
                    Some(kpb) => kpb,
                    // We lost the KeyPackageBundle apparently
                    None => return Err(TreeError::InvalidArguments),
                };
                // Update the private tree with new values
                self.private_tree = PrivateTree::from_key_package_bundle(sender_index, &own_kpb);
            }
        }
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            has_removes = true;
            let remove_proposal = &queued_proposal.proposal().as_remove().unwrap();
            let removed = NodeIndex::from(LeafIndex::from(remove_proposal.removed));
            // Check if we got removed from the group
            if removed == self.own_node_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            self.public_tree.blank_direct_path(&removed)?;
        }

        // Process adds
        let mut invitation_list = Vec::new();
        let add_proposals: Vec<AddProposal> = proposal_queue
            .filtered_by_type(ProposalType::Add)
            .map(|queued_proposal| {
                let proposal = &queued_proposal.proposal();
                proposal.as_add().unwrap()
            })
            .collect();
        let has_adds = !add_proposals.is_empty();
        // Extract KeyPackages from proposals
        let key_packages: Vec<&KeyPackage> = add_proposals.iter().map(|a| &a.key_package).collect();
        // Add new members to tree
        let added_members = self.add_nodes(&key_packages);

        // Prepare invitations
        for (i, added) in added_members.iter().enumerate() {
            invitation_list.push((added.0, add_proposals.get(i).unwrap().clone()));
        }

        // Determine if Commit needs a path field
        let path_required = has_updates || has_removes || !has_adds;

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
        })
    }

    /// Computes the tree hash
    pub fn compute_tree_hash(&self) -> Vec<u8> {
        let node_hash =
            |node_index: &NodeIndex, left_hash: &Vec<u8>, right_hash: &Vec<u8>| -> Vec<u8> {
                // We can unwrap here, because we always call this function on
                // indices within the tree.
                let option_node = self.public_tree.node(node_index).unwrap();
                if node_index.is_leaf() {
                    let option_key_package = match option_node {
                        Some(node) => Some(node.as_leaf_node().unwrap()),
                        None => None,
                    };
                    //let option_key_package: Option<&KeyPackage> =
                    //    option_node.and_then(|node: &Node| Some(node.as_leaf_node().unwrap()));
                    let leaf_node_hash_input =
                        LeafNodeHashInput::new(&node_index, option_key_package);
                    leaf_node_hash_input.hash(self.ciphersuite)
                } else {
                    let option_parent_node = match option_node {
                        Some(node) => Some(node.as_parent_node().unwrap()),
                        None => None,
                    };
                    //let option_parent_node =
                    //    option_node.and_then(|node| Some(node.as_parent_node().unwrap()));
                    let parent_node_hash_input = ParentNodeHashInput::new(
                        node_index.as_u32(),
                        option_parent_node,
                        &left_hash,
                        &right_hash,
                    );
                    parent_node_hash_input.hash(self.ciphersuite)
                }
            };

        // We can unwrap here, as the root is always within the tree.
        self.public_tree
            .fold_tree(&self.public_tree.root(), &node_hash)
            .unwrap()
    }
    /// Computes the parent hash
    pub fn compute_parent_hash(&mut self, index: NodeIndex) -> Result<Vec<u8>, TreeError> {
        let root = self.public_tree.root();
        // This should only happen when the group only contains one member
        if index == root {
            return Ok(vec![]);
        }

        // Clone the ciphersuite, so we can use it in the closure without having
        // to borrow `&self`.
        let ciphersuite = self.ciphersuite.clone();

        let f = |node_option: &mut Option<Node>, hash: Vec<u8>| -> Vec<u8> {
            if hash.is_empty() {
                node_option.as_ref().unwrap().hash(&ciphersuite).unwrap()
            } else {
                match node_option.take() {
                    Some(mut node) => {
                        match node {
                            // If it's a leaf node, put the node back and return
                            // the hash.
                            Node::Leaf(_) => {
                                node_option.replace(node);
                                hash
                            }
                            Node::Parent(ref mut parent_node) => {
                                parent_node.set_parent_hash(hash);
                                let hash = node.hash(&ciphersuite).unwrap();
                                node_option.replace(node);
                                hash
                            }
                        }
                    }
                    // If it's a blank node, return the input hash.
                    None => hash,
                }
            }
        };
        Ok(self.public_tree.direct_path_map(&index, &f)?)
    }
    /// Verifies the integrity of a public tree
    pub fn verify_integrity(ciphersuite: &Ciphersuite, nodes: &[Option<Node>]) -> bool {
        let node_count = NodeIndex::from(nodes.len());
        // TODO: This is cloning the given tree for now. Will fix this with #293.
        let tree = BlankedTree::from(nodes.to_vec());
        for i in 0..node_count.as_usize() {
            let node_option = tree.node(&NodeIndex::from(i)).unwrap();
            if let Some(node) = node_option {
                match node {
                    Node::Parent(_) => {
                        let left_index = tree.left(NodeIndex::from(i));
                        let right_index = tree.right(NodeIndex::from(i));
                        if right_index.is_err() || left_index.is_err() {
                            return false;
                        }
                        // We can unwrap the following two, because we already
                        // checked if the indices are within the tree.
                        let left_option = tree.node(&left_index.unwrap()).unwrap();
                        let right_option = tree.node(&right_index.unwrap()).unwrap();
                        let own_hash = node.hash(ciphersuite).unwrap();
                        if let Some(right) = right_option {
                            if let Some(left) = left_option {
                                let left_parent_hash = left.parent_hash().unwrap_or_else(Vec::new);
                                let right_parent_hash =
                                    right.parent_hash().unwrap_or_else(Vec::new);
                                if (left_parent_hash != own_hash) && (right_parent_hash != own_hash)
                                {
                                    return false;
                                }
                                if left_parent_hash == right_parent_hash {
                                    return false;
                                }
                            } else if right.parent_hash().unwrap() != own_hash {
                                return false;
                            }
                        } else if let Some(left) = left_option {
                            if left.parent_hash().unwrap() != own_hash {
                                return false;
                            }
                        }
                    }
                    Node::Leaf(key_package) => {
                        if i % 2 != 0 || key_package.verify().is_err() {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }
}

/// This struct contain the return vallues of the `apply_proposals()` function
pub struct ApplyProposalsValues {
    pub path_required: bool,
    pub self_removed: bool,
    pub invitation_list: Vec<(NodeIndex, AddProposal)>,
}

impl ApplyProposalsValues {
    /// This function creates a `HashSet` of node indexes of the new nodes that
    /// were added to the tree. The `HashSet` will be querried by the
    /// `resolve()` function to filter out those nodes from the resolution.
    pub fn exclusion_list(&self) -> HashSet<&NodeIndex> {
        // Collect the new leaves' indexes so we can filter them out in the resolution
        // later
        let new_leaves_indexes: HashSet<&NodeIndex> =
            HashSet::from_iter(self.invitation_list.iter().map(|(index, _)| index));
        new_leaves_indexes
    }
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<0..2^32-1>;
/// } UpdatePathNode;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub public_key: HPKEPublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     KeyPackage leaf_key_package;
///     UpdatePathNode nodes<0..2^32-1>;
/// } UpdatePath;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

impl UpdatePath {
    /// Create a new update path.
    fn new(leaf_key_package: KeyPackage, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes,
        }
    }
}
