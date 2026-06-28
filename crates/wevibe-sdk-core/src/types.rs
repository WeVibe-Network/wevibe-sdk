use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPack {
    pub pack_id: String,
    pub org_id: String,
    pub epoch_id: u32,
    pub task_description: String,
    pub approach: String,
    pub anti_patterns: Vec<String>,
    pub outcome: String,
    pub stack: Vec<String>,
    pub contributor_pubkey: String,
    pub approval_record_hash: Option<String>,
    pub export_policy: ExportPolicy,
    pub created_at: String,
    pub freshness_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExportPolicy {
    LocalOnly,
    AllowList,
    Unrestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConfig {
    pub org_id: String,
    pub org_name: String,
    pub leader_pubkey: String,
    pub current_epoch: u32,
    pub egress_mode: ExportPolicy,
    pub allowed_providers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationQueueEntry {
    pub submission_hash: String,
    pub org_id: String,
    pub epoch_id: u32,
    pub contributor_pubkey: String,
    pub stack_hint: Vec<String>,
    pub created_at: String,
    pub status: SubmissionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    PendingKeyword,
    PendingChain,
    Committed,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReceipt {
    pub receipt_id: String,
    pub org_id: String,
    pub billing_epoch: u32,
    pub access_epochs: Vec<u32>,
    pub agent_pubkey: String,
    pub query_commitment: String,
    pub result_commitment: String,
    pub agent_signature: String,
    pub node_signature: String,
    pub created_at: String,
}
