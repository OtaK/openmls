(function() {var implementors = {};
implementors["openmls"] = [{"text":"impl UnwindSafe for HpkeCiphertext","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Secret","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AeadKey","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ReuseGuard","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AeadNonce","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Signature","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for SignaturePrivateKey","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for SignaturePublicKey","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for SignatureKeypair","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Ciphersuite","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CiphersuiteName","synthetic":true,"types":[]},{"text":"impl UnwindSafe for HKDFError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for AEADError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Cursor","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CodecError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for VecSize","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CONFIG","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Config","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ProtocolVersion","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Certificate","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Credential","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for BasicCredential","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for CredentialBundle","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CredentialError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CredentialType","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MLSCredentialType","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ConfigError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Error","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ExtensionStruct","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ExtensionError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ExtensionType","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CapabilitiesExtension","synthetic":true,"types":[]},{"text":"impl UnwindSafe for KeyIDExtension","synthetic":true,"types":[]},{"text":"impl UnwindSafe for LifetimeExtension","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ParentHashExtension","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for RatchetTreeExtension","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MLSPlaintext","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSCiphertext","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MLSPlaintextTBS","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSSenderData","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSCiphertextSenderDataAAD","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MLSCiphertextContent","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSCiphertextContentAAD","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MLSPlaintextCommitContent","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSPlaintextCommitAuthData","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSPlaintextError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for MLSCiphertextError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ContentType","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MLSPlaintextContentType","synthetic":true,"types":[]},{"text":"impl UnwindSafe for Sender","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SenderType","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupId","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupEpoch","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupContext","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupConfig","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for WelcomeError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ApplyCommitError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for DecryptionError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for CreateCommitError","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for ManagedGroup","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupError","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for MlsGroup","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for KeyPackage","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for KeyPackageBundle","synthetic":true,"types":[]},{"text":"impl UnwindSafe for KeyPackageError","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Commit","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ConfirmationTag","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for GroupInfo","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PathSecret","synthetic":true,"types":[]},{"text":"impl UnwindSafe for GroupSecrets","synthetic":true,"types":[]},{"text":"impl UnwindSafe for EncryptedGroupSecrets","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Welcome","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ProposalID","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for QueuedProposal","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for ProposalQueue","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for AddProposal","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for UpdateProposal","synthetic":true,"types":[]},{"text":"impl UnwindSafe for RemoveProposal","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ProposalType","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Proposal","synthetic":true,"types":[]},{"text":"impl UnwindSafe for LeafIndex","synthetic":true,"types":[]},{"text":"impl UnwindSafe for HkdfLabel","synthetic":true,"types":[]},{"text":"impl UnwindSafe for EpochSecrets","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for RatchetTree","synthetic":true,"types":[]},{"text":"impl UnwindSafe for UpdatePathNode","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for UpdatePath","synthetic":true,"types":[]},{"text":"impl UnwindSafe for TreeError","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; UnwindSafe for ParentNodeHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !UnwindSafe for LeafNodeHashInput&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl UnwindSafe for NodeIndex","synthetic":true,"types":[]},{"text":"impl !UnwindSafe for Node","synthetic":true,"types":[]},{"text":"impl UnwindSafe for ParentNode","synthetic":true,"types":[]},{"text":"impl UnwindSafe for NodeType","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PathKeys","synthetic":true,"types":[]},{"text":"impl UnwindSafe for PrivateTree","synthetic":true,"types":[]},{"text":"impl UnwindSafe for TreeContext","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SecretTreeNode","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SecretTree","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SecretTreeError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SecretType","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SecretTypeError","synthetic":true,"types":[]},{"text":"impl UnwindSafe for SenderRatchet","synthetic":true,"types":[]},{"text":"impl UnwindSafe for TreeMathError","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()