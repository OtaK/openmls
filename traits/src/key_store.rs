//! # OpenMLS Key Store Trait

pub trait FromKeyStoreValue: Sized {
    type Error: std::error::Error;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToKeyStoreValue {
    type Error: std::error::Error;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error>;
}

/// The Key Store trait
#[cfg(not(feature = "async"))]
pub trait OpenMlsKeyStore: Send + Sync {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete(&self, k: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(feature = "async")]
/// Async version of the `OpenMlsKeyStore` trait
#[async_trait::async_trait(?Send)]
pub trait OpenMlsKeyStore {
    type Error: std::error::Error;

    async fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>;
    async fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Result<V, Self::Error>;
    async fn delete<V: FromKeyStoreValue>(&self, k: &[u8]) -> Result<(), Self::Error>;
}
