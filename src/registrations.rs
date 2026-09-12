//! Read-only access to authenticated Station registrations in a shared deployment.
use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use arkret_models_integration::PushRegistrationRecord;
use arkret_wire::{DeviceId, DidCoreId, PushTargetId};
use serde::Deserialize;

use crate::postgres_support::PostgresPool;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationSourceConfig {
    pub postgres_url: String,
}

impl std::fmt::Debug for RegistrationSourceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrationSourceConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct RegistrationDirectory {
    sources: BTreeMap<DidCoreId, PostgresPool>,
}

impl RegistrationDirectory {
    pub fn new(config: &BTreeMap<DidCoreId, RegistrationSourceConfig>) -> Result<Self> {
        let sources = config
            .iter()
            .map(|(source, config)| {
                Ok((
                    source.clone(),
                    PostgresPool::new(
                        &config.postgres_url,
                        format!("push registrations for {source}"),
                    )?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self { sources })
    }

    pub async fn resolve(
        &self,
        source: &DidCoreId,
        target: &PushTargetId,
        device: &DeviceId,
        gateway: &str,
    ) -> Result<Option<PushRegistrationRecord>> {
        let Some(pool) = self.sources.get(source).cloned() else {
            return Ok(None);
        };
        let source = source.clone();
        let target = target.clone();
        let device = device.clone();
        let gateway = gateway.to_owned();
        tokio::task::spawn_blocking(move || pool.with_client(|client| {
            // The configured database is inside the Station's trusted deployment
            // boundary. This query never creates or repairs registrations.
            let mut transaction = client.build_transaction().read_only(true).start()?;
            let rows = transaction.query("SELECT payload::text FROM public.push_devices WHERE payload->'account_id'->>'station_id' = $1 AND device_id = $2 AND push_gateway = $3", &[&source.as_str(), &device.as_str(), &gateway])?;
            let at = chrono::Utc::now();
            let mut selected = None;
            for row in rows {
                let registration: PushRegistrationRecord = serde_json::from_str(row.get::<_, &str>(0)).context("invalid durable push registration")?;
                registration.account_id.validate().context("invalid registration AccountId")?;
                if registration.account_id.station_id != source || registration.device_id != device || registration.push_gateway != gateway {
                    bail!("registration identity columns disagree with authenticated payload");
                }
                if !registration.accepts_target(&target, at) { continue; }
                if selected.replace(registration).is_some() { bail!("ambiguous registration for push target/device"); }
            }
            transaction.commit()?;
            Ok(selected)
        })).await.context("registration lookup task failed")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn postgres_registration_identity_rotation_and_removal() {
        let url = std::env::var("FLORIA_REGISTRATION_TEST_DATABASE_URL").expect(
            "set FLORIA_REGISTRATION_TEST_DATABASE_URL to an isolated Soland-initialized database",
        );
        let source = DidCoreId::new(format!(
            "ak:did_core:web:station-{}.example",
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        let other_source = DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        let configs = BTreeMap::from([
            (
                source.clone(),
                RegistrationSourceConfig {
                    postgres_url: url.clone(),
                },
            ),
            (
                other_source.clone(),
                RegistrationSourceConfig {
                    postgres_url: url.clone(),
                },
            ),
        ]);
        let directory = RegistrationDirectory::new(&configs).unwrap();
        let pool = PostgresPool::new(&url, "registration regression").unwrap();
        let mut record: PushRegistrationRecord = serde_json::from_value(serde_json::json!({
            "registration_id":format!("push_registration:{}", uuid::Uuid::new_v4().simple()),
            "account_id":{"station_id":source, "principal_id":"ak:did_core:web:alice.example"},
            "device_id":"ak:device:0196419b-0000-7000-8000-000000000001",
            "push_gateway":"https://push.example/", "push_key":"old-token", "platform":null,
            "app_id":"app", "visible_notification_opt_in":false, "push_route_id":"app",
            "push_target_id":"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "salt_epoch_id":"epoch", "expires_at":null, "retained_push_targets":[]
        }))
        .unwrap();
        let save = |record: &PushRegistrationRecord| {
            let payload = serde_json::to_string(record).unwrap();
            test_support::database(|| {
                pool.with_client(|client| {
                client.execute(
"INSERT INTO public.push_devices(id,actor_id,device_id,push_gateway,push_key,app_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7::text::jsonb) ON CONFLICT(id) DO UPDATE SET push_key=EXCLUDED.push_key,payload=EXCLUDED.payload",
&[
&record.registration_id.as_str(),
&record.account_id.principal_id.as_str(),
&record.device_id.as_str(),
&record.push_gateway,
&record.push_key.as_str(),
&record.app_id,
&payload
],
)?;
                Ok(())
            })
.unwrap()
            });
        };
        save(&record);
        let resolved = directory
            .resolve(
                &source,
                &record.push_target_id,
                &record.device_id,
                &record.push_gateway,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.push_key.as_str(), "old-token");
        assert!(!resolved.visible_notification_opt_in);
        assert!(
            directory
                .resolve(
                    &other_source,
                    &record.push_target_id,
                    &record.device_id,
                    &record.push_gateway
                )
                .await
                .unwrap()
                .is_none()
        );
        let other_device = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap();
        assert!(
            directory
                .resolve(
                    &source,
                    &record.push_target_id,
                    &other_device,
                    &record.push_gateway
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            directory
                .resolve(
                    &source,
                    &record.push_target_id,
                    &record.device_id,
                    "https://other-gateway.example/"
                )
                .await
                .unwrap()
                .is_none()
        );
        record.push_key = arkret_models_integration::PushKey::new("rotated-token").unwrap();
        record.visible_notification_opt_in = true;
        save(&record);
        let rotated = directory
            .resolve(
                &source,
                &record.push_target_id,
                &record.device_id,
                &record.push_gateway,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rotated.push_key.as_str(), "rotated-token");
        assert!(rotated.visible_notification_opt_in);
        record.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        save(&record);
        assert!(
            directory
                .resolve(
                    &source,
                    &record.push_target_id,
                    &record.device_id,
                    &record.push_gateway
                )
                .await
                .unwrap()
                .is_none()
        );
        test_support::database(|| {
            pool.with_client(|client| {
                client.execute(
                    "DELETE FROM public.push_devices WHERE id=$1",
                    &[&record.registration_id.as_str()],
                )?;
                Ok(())
            })
            .unwrap()
        });
        assert!(
            directory
                .resolve(
                    &source,
                    &record.push_target_id,
                    &record.device_id,
                    &record.push_gateway
                )
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    /// Synchronous postgres owns a runtime; fixtures must execute outside Tokio.
    pub(crate) fn database<T: Send>(work: impl FnOnce() -> T + Send) -> T {
        std::thread::scope(|scope| scope.spawn(work).join().expect("database fixture panicked"))
    }

    pub(crate) const SOURCE: &str = "ak:did_core:web:sync.example.com";
    pub(crate) const GATEWAY: &str = "http://127.0.0.1:5000/";
    fn database_url() -> String {
        std::env::var("FLORIA_REGISTRATION_TEST_DATABASE_URL").expect("set FLORIA_REGISTRATION_TEST_DATABASE_URL to a Soland-initialized isolated test database")
    }
    pub(crate) fn directory() -> RegistrationDirectory {
        RegistrationDirectory::new(&BTreeMap::from([(
            DidCoreId::new(SOURCE).unwrap(),
            RegistrationSourceConfig {
                postgres_url: database_url(),
            },
        )]))
        .unwrap()
    }
    pub(crate) fn device(app_id: &str, push_key: &str, device_id: &str) -> serde_json::Value {
        let record: PushRegistrationRecord = serde_json::from_value(serde_json::json!({
            "registration_id":format!("push_registration:{}", device_id.rsplit(':').next().unwrap()),
            "account_id":{"principal_id":"ak:did_core:web:fixture.example", "station_id":SOURCE},
            "device_id":device_id, "push_gateway":GATEWAY, "push_key":push_key, "platform":null,
            "app_id":app_id, "visible_notification_opt_in":true, "push_route_id":app_id,
            "push_target_id":"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "salt_epoch_id":"epoch", "expires_at":null, "retained_push_targets":[]
        })).unwrap();
        let payload = serde_json::to_string(&record).unwrap();
        database(|| {
            PostgresPool::new(&database_url(), "push fixture registration").unwrap()
.with_client(|client| {
            client.execute(
"INSERT INTO public.push_devices(id,actor_id,device_id,push_gateway,push_key,app_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7::text::jsonb) ON CONFLICT(id) DO UPDATE SET actor_id=EXCLUDED.actor_id,device_id=EXCLUDED.device_id,push_gateway=EXCLUDED.push_gateway,push_key=EXCLUDED.push_key,app_id=EXCLUDED.app_id,payload=EXCLUDED.payload",
&[
&record.registration_id.as_str(),
&record.account_id.principal_id.as_str(),
&record.device_id.as_str(),
&record.push_gateway,
&record.push_key.as_str(),
&record.app_id,
&payload
],
)?;
            Ok(())
        })
.unwrap()
        });
        serde_json::json!({"device_id":device_id})
    }
}
