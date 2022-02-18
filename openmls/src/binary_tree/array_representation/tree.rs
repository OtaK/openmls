//! A binary tree implementation for use with MLS.
//!
//! # About
//!
//! This module contains an implementation of a binary tree based on an array
//! representation. The main [`ABinaryTree`] struct is generally immutable, but
//! allows the creation of an [`AbDiff`] struct, where changes can be made before
//! merging it back into an existing tree.
//!
//! # Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable
//! [`LibraryError`](ABinaryTreeError::LibraryError). This means that some
//! functions that are not expected to fail and throw an error, will still
//! return a [`Result`] since they may throw a
//! [`LibraryError`](ABinaryTreeError::LibraryError).

use std::convert::TryFrom;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::diff::{AbDiff, StagedAbDiff};
use crate::{
    binary_tree::{LeafIndex, TreeSize},
    error::LibraryError,
};

/// The [`NodeIndex`] is used to index nodes.
pub(in crate::binary_tree) type NodeIndex = u32;

/// Given a [`LeafIndex`], compute the position of the corresponding [`NodeIndex`].
pub(super) fn to_node_index(leaf_index: LeafIndex) -> NodeIndex {
    leaf_index * 2
}

#[cfg_attr(test, derive(PartialEq))]
// 16bit platforms are not supported, because we require usize >= u32
#[cfg(not(target_pointer_width = "16"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes. Each tree has to consist of at least one node.
pub(crate) struct ABinaryTree<T: Clone + Debug> {
    nodes: Vec<T>,
}

impl<T: Clone + Debug> TryFrom<Vec<T>> for ABinaryTree<T> {
    type Error = ABinaryTreeError;

    fn try_from(nodes: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(nodes)
    }
}

impl<T: Clone + Debug> ABinaryTree<T> {
    /// Create a tree from the given vector of nodes. The vector of nodes can't
    /// be empty and has to yield a full, left-balanced binary tree. The nodes
    /// in the tree are ordered in the array-representation. This function
    /// throws a [`ABinaryTreeError::InvalidNumberOfNodes`] error if the number of nodes does not
    /// allow the creation of a full, left-balanced binary tree and an
    /// [`ABinaryTreeError::OutOfRange`] error if the number of given nodes exceeds the range of
    /// [`NodeIndex`].
    pub(crate) fn new(nodes: Vec<T>) -> Result<Self, ABinaryTreeError> {
        if nodes.len() > NodeIndex::MAX as usize {
            return Err(ABinaryTreeError::OutOfRange);
        }
        if nodes.len() % 2 != 1 {
            return Err(ABinaryTreeError::InvalidNumberOfNodes);
        }
        Ok(ABinaryTree { nodes })
    }

    /// Obtain a reference to the data contained in the node at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns [`ABinaryTreeError::OutOfBounds`]
    /// if the index is larger than the size of the tree.
    pub(in crate::binary_tree) fn node_by_index(
        &self,
        node_index: NodeIndex,
    ) -> Result<&T, ABinaryTreeError> {
        self.nodes
            .get(node_index as usize)
            .ok_or(ABinaryTreeError::OutOfBounds)
    }

    /// Return the number of nodes in the tree.
    pub(in crate::binary_tree) fn size(&self) -> NodeIndex {
        self.nodes.len() as NodeIndex
    }

    /// Return the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> TreeSize {
        // This works, because the tree always has at least one leaf.
        ((self.size() - 1) / 2) + 1
    }

    /// Return a vector of leaves sorted according to their position in the tree
    /// from left to right. This function should not fail and only returns a
    /// [`Result`], because it might throw a
    /// [`LibraryError`](ABinaryTreeError::LibraryError).
    pub(crate) fn leaves(&self) -> Vec<&T> {
        self.nodes()
            .iter()
            .enumerate()
            .filter_map(|(index, node)| if index % 2 == 0 { Some(node) } else { None })
            .collect()
    }

    /// Creates and returns an empty [`AbDiff`].
    pub(crate) fn empty_diff(&self) -> AbDiff<'_, T> {
        self.into()
    }

    /// Merges the changes applied to the [`StagedAbDiff`] into the tree.
    /// Depending on the changes made to the diff, this can either increase or
    /// decrease the size of the tree, although not beyond the minimum size of
    /// leaf or the maximum size of `u32::MAX`.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](ABinaryTreeError::LibraryError).
    pub(crate) fn merge_diff(&mut self, diff: StagedAbDiff<T>) -> Result<(), LibraryError> {
        // If the size of the diff is smaller than the tree, truncate the tree
        // to the size of the diff.
        self.nodes.truncate(diff.tree_size() as usize);

        // Iterate over the BTreeMap in order of indices.
        for (node_index, diff_node) in diff.diff().into_iter() {
            match node_index {
                // If the node would extend the tree, push it to the vector of nodes.
                node_index if node_index == self.size() => self.nodes.push(diff_node),
                // If the node index points too far outside of the tree,
                // something has gone wrong.
                node_index if node_index > self.size() => {
                    return Err(LibraryError::custom("Node is outside the tree"))
                }
                // If the node_index points to somewhere within the size of the
                // tree, do a swap-remove.
                node_index => {
                    // Perform swap-remove.
                    self.nodes[node_index as usize] = diff_node;
                }
            }
        }
        Ok(())
    }

    /// Export the nodes of the tree in the array representation.
    pub(crate) fn nodes(&self) -> &[T] {
        &self.nodes
    }

    /// Return a reference to the leaf at the given `LeafIndex`.
    ///
    /// Returns an error if the leaf is outside of the tree.
    pub(crate) fn leaf(&self, leaf_index: LeafIndex) -> Result<&T, ABinaryTreeError> {
        let node_index = to_node_index(leaf_index) as usize;
        self.nodes
            .get(node_index)
            .ok_or(ABinaryTreeError::OutOfBounds)
    }
}

/// Binary Tree error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ABinaryTreeError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Adding nodes exceeds the maximum possible size of the tree.
    #[error("Adding nodes exceeds the maximum possible size of the tree.")]
    OutOfRange,
    /// Not enough nodes to remove.
    #[error("Not enough nodes to remove.")]
    InvalidNumberOfNodes,
    /// The given index is outside of the tree.
    #[error("The given index is outside of the tree.")]
    OutOfBounds,
}
