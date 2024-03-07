use ockam::identity::models::CredentialAndPurposeKey;
use ockam::identity::{CredentialRetrieverCreator, Identifier, RemoteCredentialRetrieverInfo};
use std::fmt::Display;
use std::sync::Arc;

#[derive(Clone)]
pub struct CredentialRetrieverCreators {
    pub(crate) project_member: Option<Arc<dyn CredentialRetrieverCreator>>,
    pub(crate) project_admin: Option<Arc<dyn CredentialRetrieverCreator>>,
    pub(crate) _account_admin: Option<Arc<dyn CredentialRetrieverCreator>>,
}

pub enum CredentialScope {
    ProjectMember { project_id: String },
    ProjectAdmin { project_id: String },
    AccountAdmin { account_id: String },
}

impl Display for CredentialScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            CredentialScope::ProjectMember { project_id } => {
                format!("project-member-{}", project_id)
            }
            CredentialScope::ProjectAdmin { project_id } => {
                format!("project-admin-{}", project_id)
            }
            CredentialScope::AccountAdmin { account_id } => {
                format!("account-admin-{}", account_id)
            }
        };
        write!(f, "{}", str)
    }
}

#[derive(Debug)]
pub enum NodeManagerCredentialRetrieverOptions {
    None,
    CacheOnly {
        issuer: Identifier,
        project_id: String,
    },
    Remote {
        info: RemoteCredentialRetrieverInfo,
        project_id: String,
    },
    InMemory(CredentialAndPurposeKey),
}

pub struct NodeManagerTrustOptions {
    pub(super) project_member_credential_retriever_options: NodeManagerCredentialRetrieverOptions,
    pub(super) project_authority: Option<Identifier>,
    pub(super) project_admin_credential_retriever_options: NodeManagerCredentialRetrieverOptions,
    pub(super) _account_admin_credential_retriever_options: NodeManagerCredentialRetrieverOptions,
}

impl NodeManagerTrustOptions {
    pub fn new(
        project_member_credential_retriever_options: NodeManagerCredentialRetrieverOptions,
        project_admin_credential_retriever_options: NodeManagerCredentialRetrieverOptions,
        project_authority: Option<Identifier>,
        account_admin_credential_retriever_options: NodeManagerCredentialRetrieverOptions,
    ) -> Self {
        Self {
            project_member_credential_retriever_options,
            project_admin_credential_retriever_options,
            project_authority,
            _account_admin_credential_retriever_options: account_admin_credential_retriever_options,
        }
    }
}
