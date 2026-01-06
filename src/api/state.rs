use std::sync::Arc;
use sqlx::{Pool, Sqlite};
use ark_groth16::VerifyingKey;
use ark_bn254::Bn254;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Sqlite>,
    pub vk: Arc<VerifyingKey<Bn254>>,
    pub config: Arc<Config>,
}
