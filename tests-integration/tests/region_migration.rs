// Copyright 2023 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;
use std::time::Duration;

use client::{DEFAULT_CATALOG_NAME, DEFAULT_SCHEMA_NAME};
use common_meta::key::{RegionDistribution, TableMetadataManagerRef};
use common_meta::peer::Peer;
use common_query::Output;
use common_recordbatch::RecordBatches;
use common_telemetry::info;
use common_test_util::recordbatch::check_output_stream;
use common_test_util::temp_dir::create_temp_dir;
use common_wal::config::kafka::{DatanodeKafkaConfig, MetaSrvKafkaConfig};
use common_wal::config::{DatanodeWalConfig, MetaSrvWalConfig};
use datatypes::prelude::ScalarVector;
use datatypes::value::Value;
use datatypes::vectors::{Helper, UInt64Vector};
use frontend::error::Result as FrontendResult;
use frontend::instance::Instance;
use futures::future::BoxFuture;
use meta_srv::error::Result as MetaResult;
use meta_srv::metasrv::SelectorContext;
use meta_srv::procedure::region_migration::RegionMigrationProcedureTask;
use meta_srv::selector::{Namespace, Selector, SelectorOptions};
use servers::query_handler::sql::SqlQueryHandler;
use session::context::{QueryContext, QueryContextRef};
use store_api::storage::RegionId;
use table::metadata::TableId;
use tests_integration::cluster::{GreptimeDbCluster, GreptimeDbClusterBuilder};
use tests_integration::test_util::{get_test_store_config, StorageType, PEER_PLACEHOLDER_ADDR};
use uuid::Uuid;

const TEST_TABLE_NAME: &str = "migration_target";

#[macro_export]
macro_rules! region_migration_test {
    ($service:ident, $($(#[$meta:meta])* $test:ident),*,) => {
        paste::item! {
            mod [<integration_region_migration_ $service:lower _test>] {
                $(
                    #[tokio::test(flavor = "multi_thread")]
                    $(
                        #[$meta]
                    )*
                    async fn [< $test >]() {
                        let store_type = tests_integration::test_util::StorageType::$service;
                        if store_type.test_on() {
                            common_telemetry::init_default_ut_logging();
                            tests_integration::test_util::run_test_with_kafka_wal(|endpoints| {
                                Box::pin(async move { $crate::region_migration::$test(store_type, endpoints).await })
                            })
                            .await
                        }

                    }
                )*
            }
        }
    };
}

#[macro_export]
macro_rules! region_migration_tests {
    ($($service:ident),*) => {
        $(
            region_migration_test!(
                $service,

                test_region_migration,
                test_region_migration_by_sql,
                test_region_migration_multiple_regions,
                test_region_migration_all_regions,
                test_region_migration_incorrect_from_peer,
                test_region_migration_incorrect_region_id,
            );
        )*
    };
}

/// A naive region migration test.
pub async fn test_region_migration(store_type: StorageType, endpoints: Vec<String>) {
    let cluster_name = "test_region_migration";
    let peer_factory = |id| Peer {
        id,
        addr: PEER_PLACEHOLDER_ADDR.to_string(),
    };

    // Prepares test cluster.
    let (store_config, _guard) = get_test_store_config(&store_type);
    let home_dir = create_temp_dir("test_migration_data_home");
    let datanodes = 5u64;
    let builder = GreptimeDbClusterBuilder::new(cluster_name).await;
    let const_selector = Arc::new(ConstNodeSelector::new(vec![
        peer_factory(1),
        peer_factory(2),
        peer_factory(3),
    ]));
    let cluster = builder
        .with_datanodes(datanodes as u32)
        .with_store_config(store_config)
        .with_wal_config(DatanodeWalConfig::Kafka(DatanodeKafkaConfig {
            broker_endpoints: endpoints.clone(),
            linger: Duration::from_millis(25),
            ..Default::default()
        }))
        .with_meta_wal_config(MetaSrvWalConfig::Kafka(MetaSrvKafkaConfig {
            broker_endpoints: endpoints,
            num_topics: 3,
            topic_name_prefix: Uuid::new_v4().to_string(),
            ..Default::default()
        }))
        .with_shared_home_dir(Arc::new(home_dir))
        .with_meta_selector(const_selector.clone())
        .build()
        .await;
    let mut logical_timer = 1685508715000;
    let table_metadata_manager = cluster.meta_srv.table_metadata_manager().clone();

    // Prepares test table.
    let table_id = prepare_testing_table(&cluster).await;

    // Inserts data
    let results = insert_values(&cluster.frontend, logical_timer).await;
    logical_timer += 1000;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // The region distribution
    let mut distribution = find_region_distribution(&table_metadata_manager, table_id).await;

    // Selecting target of region migration.
    let region_migration_manager = cluster.meta_srv.region_migration_manager();
    let (from_peer_id, from_regions) = distribution.pop_first().unwrap();
    info!(
        "Selecting from peer: {from_peer_id}, and regions: {:?}",
        from_regions
    );
    let (to_peer_id, mut to_regions) = distribution.pop_first().unwrap();
    info!(
        "Selecting to peer: {to_peer_id}, and regions: {:?}",
        to_regions
    );

    let region_id = RegionId::new(table_id, from_regions[0]);
    // Trigger region migration.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    info!("Started region procedure: {}!", procedure.unwrap());

    // Prepares expected region distribution.
    to_regions.extend(from_regions);
    // Keeps asc order.
    to_regions.sort();
    distribution.insert(to_peer_id, to_regions);

    // Waits condition
    wait_condition(
        Duration::from_secs(10),
        Box::pin(async move {
            loop {
                let region_migration =
                    find_region_distribution(&table_metadata_manager, table_id).await;
                if region_migration == distribution {
                    info!("Found new distribution: {region_migration:?}");
                    break;
                } else {
                    info!("Found the unexpected distribution: {region_migration:?}, expected: {distribution:?}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }),
    )
    .await;

    // Inserts more table.
    let results = insert_values(&cluster.frontend, logical_timer).await;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // Asserts the writes.
    assert_values(&cluster.frontend).await;

    // Triggers again.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    assert!(procedure.is_none());
}

/// A naive region migration test by SQL function
pub async fn test_region_migration_by_sql(store_type: StorageType, endpoints: Vec<String>) {
    let cluster_name = "test_region_migration";
    let peer_factory = |id| Peer {
        id,
        addr: PEER_PLACEHOLDER_ADDR.to_string(),
    };

    // Prepares test cluster.
    let (store_config, _guard) = get_test_store_config(&store_type);
    let home_dir = create_temp_dir("test_migration_data_home");
    let datanodes = 5u64;
    let builder = GreptimeDbClusterBuilder::new(cluster_name).await;
    let const_selector = Arc::new(ConstNodeSelector::new(vec![
        peer_factory(1),
        peer_factory(2),
        peer_factory(3),
    ]));
    let cluster = builder
        .with_datanodes(datanodes as u32)
        .with_store_config(store_config)
        .with_wal_config(DatanodeWalConfig::Kafka(DatanodeKafkaConfig {
            broker_endpoints: endpoints.clone(),
            linger: Duration::from_millis(25),
            ..Default::default()
        }))
        .with_meta_wal_config(MetaSrvWalConfig::Kafka(MetaSrvKafkaConfig {
            broker_endpoints: endpoints,
            num_topics: 3,
            topic_name_prefix: Uuid::new_v4().to_string(),
            ..Default::default()
        }))
        .with_shared_home_dir(Arc::new(home_dir))
        .with_meta_selector(const_selector.clone())
        .build()
        .await;
    let mut logical_timer = 1685508715000;

    // Prepares test table.
    let table_id = prepare_testing_table(&cluster).await;

    // Inserts data
    let results = insert_values(&cluster.frontend, logical_timer).await;
    logical_timer += 1000;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // The region distribution
    let mut distribution = find_region_distribution_by_sql(&cluster).await;

    let old_distribution = distribution.clone();

    // Selecting target of region migration.
    let region_migration_manager = cluster.meta_srv.region_migration_manager();
    let (from_peer_id, from_regions) = distribution.pop_first().unwrap();
    info!(
        "Selecting from peer: {from_peer_id}, and regions: {:?}",
        from_regions
    );
    let (to_peer_id, to_regions) = distribution.pop_first().unwrap();
    info!(
        "Selecting to peer: {to_peer_id}, and regions: {:?}",
        to_regions
    );

    let region_id = RegionId::new(table_id, from_regions[0]);
    // Trigger region migration.
    let procedure_id =
        trigger_migration_by_sql(&cluster, region_id.as_u64(), from_peer_id, to_peer_id).await;

    info!("Started region procedure: {}!", procedure_id);

    // Waits condition by checking procedure state
    let frontend = cluster.frontend.clone();
    wait_condition(
        Duration::from_secs(10),
        Box::pin(async move {
            loop {
                let state = query_procedure_by_sql(&frontend, &procedure_id).await;
                if state == "{\"status\":\"Done\"}" {
                    info!("Migration done: {state}");
                    break;
                } else {
                    info!("Migration not finished: {state}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }),
    )
    .await;

    // Inserts more table.
    let results = insert_values(&cluster.frontend, logical_timer).await;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // Asserts the writes.
    assert_values(&cluster.frontend).await;

    // Triggers again.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    assert!(procedure.is_none());

    let new_distribution = find_region_distribution_by_sql(&cluster).await;

    assert_ne!(old_distribution, new_distribution);
}

/// A region migration test for a region server contains multiple regions of the table.
pub async fn test_region_migration_multiple_regions(
    store_type: StorageType,
    endpoints: Vec<String>,
) {
    let cluster_name = "test_region_migration_multiple_regions";
    let peer_factory = |id| Peer {
        id,
        addr: PEER_PLACEHOLDER_ADDR.to_string(),
    };

    // Prepares test cluster.
    let (store_config, _guard) = get_test_store_config(&store_type);
    let home_dir = create_temp_dir("test_region_migration_multiple_regions_data_home");
    let datanodes = 5u64;
    let builder = GreptimeDbClusterBuilder::new(cluster_name).await;
    let const_selector = Arc::new(ConstNodeSelector::new(vec![
        peer_factory(1),
        peer_factory(2),
        peer_factory(2),
    ]));
    let cluster = builder
        .with_datanodes(datanodes as u32)
        .with_store_config(store_config)
        .with_wal_config(DatanodeWalConfig::Kafka(DatanodeKafkaConfig {
            broker_endpoints: endpoints.clone(),
            linger: Duration::from_millis(25),
            ..Default::default()
        }))
        .with_meta_wal_config(MetaSrvWalConfig::Kafka(MetaSrvKafkaConfig {
            broker_endpoints: endpoints,
            num_topics: 3,
            topic_name_prefix: Uuid::new_v4().to_string(),
            ..Default::default()
        }))
        .with_shared_home_dir(Arc::new(home_dir))
        .with_meta_selector(const_selector.clone())
        .build()
        .await;
    let mut logical_timer = 1685508715000;
    let table_metadata_manager = cluster.meta_srv.table_metadata_manager().clone();

    // Prepares test table.
    let table_id = prepare_testing_table(&cluster).await;

    // Inserts data
    let results = insert_values(&cluster.frontend, logical_timer).await;
    logical_timer += 1000;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // The region distribution
    let mut distribution = find_region_distribution(&table_metadata_manager, table_id).await;
    assert_eq!(distribution.len(), 2);

    // Selecting target of region migration.
    let region_migration_manager = cluster.meta_srv.region_migration_manager();
    let (peer_1, peer_1_regions) = distribution.pop_first().unwrap();
    let (peer_2, peer_2_regions) = distribution.pop_first().unwrap();

    // Picks the peer only contains as from peer.
    let ((from_peer_id, from_regions), (to_peer_id, mut to_regions)) = if peer_1_regions.len() == 1
    {
        ((peer_1, peer_1_regions), (peer_2, peer_2_regions))
    } else {
        ((peer_2, peer_2_regions), (peer_1, peer_1_regions))
    };

    info!(
        "Selecting from peer: {from_peer_id}, and regions: {:?}",
        from_regions
    );
    info!(
        "Selecting to peer: {to_peer_id}, and regions: {:?}",
        to_regions
    );

    let region_id = RegionId::new(table_id, from_regions[0]);
    // Trigger region migration.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    info!("Started region procedure: {}!", procedure.unwrap());

    // Prepares expected region distribution.
    to_regions.extend(from_regions);
    // Keeps asc order.
    to_regions.sort();
    distribution.insert(to_peer_id, to_regions);

    // Waits condition
    wait_condition(
        Duration::from_secs(10),
        Box::pin(async move {
            loop {
                let region_migration =
                    find_region_distribution(&table_metadata_manager, table_id).await;
                if region_migration == distribution {
                    info!("Found new distribution: {region_migration:?}");
                    break;
                } else {
                    info!("Found the unexpected distribution: {region_migration:?}, expected: {distribution:?}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }),
    )
    .await;

    // Inserts more table.
    let results = insert_values(&cluster.frontend, logical_timer).await;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // Asserts the writes.
    assert_values(&cluster.frontend).await;

    // Triggers again.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    assert!(procedure.is_none());
}

/// A region migration test for a region server contains all regions of the table.
pub async fn test_region_migration_all_regions(store_type: StorageType, endpoints: Vec<String>) {
    let cluster_name = "test_region_migration_all_regions";
    let peer_factory = |id| Peer {
        id,
        addr: PEER_PLACEHOLDER_ADDR.to_string(),
    };

    // Prepares test cluster.
    let (store_config, _guard) = get_test_store_config(&store_type);
    let home_dir = create_temp_dir("test_region_migration_all_regions_data_home");
    let datanodes = 5u64;
    let builder = GreptimeDbClusterBuilder::new(cluster_name).await;
    let const_selector = Arc::new(ConstNodeSelector::new(vec![
        peer_factory(2),
        peer_factory(2),
        peer_factory(2),
    ]));
    let cluster = builder
        .with_datanodes(datanodes as u32)
        .with_store_config(store_config)
        .with_wal_config(DatanodeWalConfig::Kafka(DatanodeKafkaConfig {
            broker_endpoints: endpoints.clone(),
            linger: Duration::from_millis(25),
            ..Default::default()
        }))
        .with_meta_wal_config(MetaSrvWalConfig::Kafka(MetaSrvKafkaConfig {
            broker_endpoints: endpoints,
            num_topics: 3,
            topic_name_prefix: Uuid::new_v4().to_string(),
            ..Default::default()
        }))
        .with_shared_home_dir(Arc::new(home_dir))
        .with_meta_selector(const_selector.clone())
        .build()
        .await;
    let mut logical_timer = 1685508715000;
    let table_metadata_manager = cluster.meta_srv.table_metadata_manager().clone();

    // Prepares test table.
    let table_id = prepare_testing_table(&cluster).await;

    // Inserts data
    let results = insert_values(&cluster.frontend, logical_timer).await;
    logical_timer += 1000;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // The region distribution
    let mut distribution = find_region_distribution(&table_metadata_manager, table_id).await;
    assert_eq!(distribution.len(), 1);

    // Selecting target of region migration.
    let region_migration_manager = cluster.meta_srv.region_migration_manager();
    let (from_peer_id, mut from_regions) = distribution.pop_first().unwrap();
    let to_peer_id = 1;
    let mut to_regions = Vec::new();
    info!(
        "Selecting from peer: {from_peer_id}, and regions: {:?}",
        from_regions
    );
    info!(
        "Selecting to peer: {to_peer_id}, and regions: {:?}",
        to_regions
    );

    let region_id = RegionId::new(table_id, from_regions[0]);
    // Trigger region migration.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    info!("Started region procedure: {}!", procedure.unwrap());

    // Prepares expected region distribution.
    to_regions.push(from_regions.remove(0));
    // Keeps asc order.
    to_regions.sort();
    distribution.insert(to_peer_id, to_regions);
    distribution.insert(from_peer_id, from_regions);

    // Waits condition
    wait_condition(
        Duration::from_secs(10),
        Box::pin(async move {
            loop {
                let region_migration =
                    find_region_distribution(&table_metadata_manager, table_id).await;
                if region_migration == distribution {
                    info!("Found new distribution: {region_migration:?}");
                    break;
                } else {
                    info!("Found the unexpected distribution: {region_migration:?}, expected: {distribution:?}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }),
    )
    .await;

    // Inserts more table.
    let results = insert_values(&cluster.frontend, logical_timer).await;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // Asserts the writes.
    assert_values(&cluster.frontend).await;

    // Triggers again.
    let procedure = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(from_peer_id),
            peer_factory(to_peer_id),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap();
    assert!(procedure.is_none());
}

pub async fn test_region_migration_incorrect_from_peer(
    store_type: StorageType,
    endpoints: Vec<String>,
) {
    let cluster_name = "test_region_migration_incorrect_from_peer";
    let peer_factory = |id| Peer {
        id,
        addr: PEER_PLACEHOLDER_ADDR.to_string(),
    };

    // Prepares test cluster.
    let (store_config, _guard) = get_test_store_config(&store_type);
    let home_dir = create_temp_dir("test_region_migration_incorrect_from_peer_data_home");
    let datanodes = 5u64;
    let builder = GreptimeDbClusterBuilder::new(cluster_name).await;
    let const_selector = Arc::new(ConstNodeSelector::new(vec![
        peer_factory(1),
        peer_factory(2),
        peer_factory(3),
    ]));
    let cluster = builder
        .with_datanodes(datanodes as u32)
        .with_store_config(store_config)
        .with_wal_config(DatanodeWalConfig::Kafka(DatanodeKafkaConfig {
            broker_endpoints: endpoints.clone(),
            linger: Duration::from_millis(25),
            ..Default::default()
        }))
        .with_meta_wal_config(MetaSrvWalConfig::Kafka(MetaSrvKafkaConfig {
            broker_endpoints: endpoints,
            num_topics: 3,
            topic_name_prefix: Uuid::new_v4().to_string(),
            ..Default::default()
        }))
        .with_shared_home_dir(Arc::new(home_dir))
        .with_meta_selector(const_selector.clone())
        .build()
        .await;
    let logical_timer = 1685508715000;
    let table_metadata_manager = cluster.meta_srv.table_metadata_manager().clone();

    // Prepares test table.
    let table_id = prepare_testing_table(&cluster).await;

    // Inserts data
    let results = insert_values(&cluster.frontend, logical_timer).await;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // The region distribution
    let distribution = find_region_distribution(&table_metadata_manager, table_id).await;
    assert_eq!(distribution.len(), 3);
    let region_migration_manager = cluster.meta_srv.region_migration_manager();

    let region_id = RegionId::new(table_id, 1);

    // Trigger region migration.
    let err = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(5),
            peer_factory(1),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        meta_srv::error::Error::InvalidArguments { .. }
    ));
}

pub async fn test_region_migration_incorrect_region_id(
    store_type: StorageType,
    endpoints: Vec<String>,
) {
    let cluster_name = "test_region_migration_incorrect_region_id";
    let peer_factory = |id| Peer {
        id,
        addr: PEER_PLACEHOLDER_ADDR.to_string(),
    };

    // Prepares test cluster.
    let (store_config, _guard) = get_test_store_config(&store_type);
    let home_dir = create_temp_dir("test_region_migration_incorrect_region_id_data_home");
    let datanodes = 5u64;
    let builder = GreptimeDbClusterBuilder::new(cluster_name).await;
    let const_selector = Arc::new(ConstNodeSelector::new(vec![
        peer_factory(1),
        peer_factory(2),
        peer_factory(3),
    ]));
    let cluster = builder
        .with_datanodes(datanodes as u32)
        .with_store_config(store_config)
        .with_wal_config(DatanodeWalConfig::Kafka(DatanodeKafkaConfig {
            broker_endpoints: endpoints.clone(),
            linger: Duration::from_millis(25),
            ..Default::default()
        }))
        .with_meta_wal_config(MetaSrvWalConfig::Kafka(MetaSrvKafkaConfig {
            broker_endpoints: endpoints,
            num_topics: 3,
            topic_name_prefix: Uuid::new_v4().to_string(),
            ..Default::default()
        }))
        .with_shared_home_dir(Arc::new(home_dir))
        .with_meta_selector(const_selector.clone())
        .build()
        .await;
    let logical_timer = 1685508715000;
    let table_metadata_manager = cluster.meta_srv.table_metadata_manager().clone();

    // Prepares test table.
    let table_id = prepare_testing_table(&cluster).await;

    // Inserts data
    let results = insert_values(&cluster.frontend, logical_timer).await;
    for result in results {
        assert!(matches!(result.unwrap(), Output::AffectedRows(1)));
    }

    // The region distribution
    let distribution = find_region_distribution(&table_metadata_manager, table_id).await;
    assert_eq!(distribution.len(), 3);
    let region_migration_manager = cluster.meta_srv.region_migration_manager();

    let region_id = RegionId::new(table_id, 5);

    // Trigger region migration.
    let err = region_migration_manager
        .submit_procedure(RegionMigrationProcedureTask::new(
            0,
            region_id,
            peer_factory(2),
            peer_factory(1),
            Duration::from_millis(1000),
        ))
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        meta_srv::error::Error::RegionRouteNotFound { .. }
    ));
}

struct ConstNodeSelector {
    peers: Vec<Peer>,
}

impl ConstNodeSelector {
    fn new(peers: Vec<Peer>) -> Self {
        Self { peers }
    }
}

#[async_trait::async_trait]
impl Selector for ConstNodeSelector {
    type Context = SelectorContext;
    type Output = Vec<Peer>;

    async fn select(
        &self,
        _ns: Namespace,
        _ctx: &Self::Context,
        _opts: SelectorOptions,
    ) -> MetaResult<Self::Output> {
        Ok(self.peers.clone())
    }
}

async fn wait_condition(timeout: Duration, condition: BoxFuture<'static, ()>) {
    tokio::time::timeout(timeout, condition).await.unwrap();
}

async fn assert_values(instance: &Arc<Instance>) {
    let query_ctx = QueryContext::arc();

    let result = instance
        .do_query(
            &format!("select * from {TEST_TABLE_NAME} order by i, ts"),
            query_ctx,
        )
        .await
        .remove(0);

    let expected = "\
+----+---------------------+
| i  | ts                  |
+----+---------------------+
| 5  | 2023-05-31T04:51:55 |
| 5  | 2023-05-31T04:51:56 |
| 15 | 2023-05-31T04:51:55 |
| 15 | 2023-05-31T04:51:56 |
| 55 | 2023-05-31T04:51:55 |
| 55 | 2023-05-31T04:51:56 |
+----+---------------------+";
    check_output_stream(result.unwrap(), expected).await;
}

async fn prepare_testing_table(cluster: &GreptimeDbCluster) -> TableId {
    let sql = format!(
        r"
    CREATE TABLE {TEST_TABLE_NAME} (
        i INT PRIMARY KEY,
        ts TIMESTAMP TIME INDEX,
    ) PARTITION ON COLUMNS (i) (
        i <= 10,
        i > 10 AND i <= 50,
        i > 50
    )"
    );
    let mut result = cluster.frontend.do_query(&sql, QueryContext::arc()).await;
    let output = result.remove(0).unwrap();
    assert!(matches!(output, Output::AffectedRows(0)));

    let table = cluster
        .frontend
        .catalog_manager()
        .table(DEFAULT_CATALOG_NAME, DEFAULT_SCHEMA_NAME, TEST_TABLE_NAME)
        .await
        .unwrap()
        .unwrap();
    table.table_info().table_id()
}

async fn find_region_distribution(
    table_metadata_manager: &TableMetadataManagerRef,
    table_id: TableId,
) -> RegionDistribution {
    table_metadata_manager
        .table_route_manager()
        .get_region_distribution(table_id)
        .await
        .unwrap()
        .unwrap()
}

/// Find region distribution by SQL query
async fn find_region_distribution_by_sql(cluster: &GreptimeDbCluster) -> RegionDistribution {
    let query_ctx = QueryContext::arc();

    let Output::Stream(stream, _) = run_sql(
        &cluster.frontend,
        &format!(r#"select b.peer_id as datanode_id,
                           a.greptime_partition_id as region_id
                    from information_schema.partitions a left join information_schema.greptime_region_peers b
                    on a.greptime_partition_id = b.region_id
                    where a.table_name='{TEST_TABLE_NAME}' order by datanode_id asc"#
        ),
        query_ctx.clone(),
    )
        .await.unwrap() else {
            unreachable!();
        };

    let recordbatches = RecordBatches::try_collect(stream).await.unwrap();

    info!("SQL result:\n {}", recordbatches.pretty_print().unwrap());

    let mut distribution = RegionDistribution::new();

    for batch in recordbatches.take() {
        let datanode_ids: &UInt64Vector =
            unsafe { Helper::static_cast(batch.column_by_name("datanode_id").unwrap()) };
        let region_ids: &UInt64Vector =
            unsafe { Helper::static_cast(batch.column_by_name("region_id").unwrap()) };

        for (datanode_id, region_id) in datanode_ids.iter_data().zip(region_ids.iter_data()) {
            let (Some(datanode_id), Some(region_id)) = (datanode_id, region_id) else {
                unreachable!();
            };

            let region_id = RegionId::from_u64(region_id);
            distribution
                .entry(datanode_id)
                .or_default()
                .push(region_id.region_number());
        }
    }

    distribution
}

/// Trigger the region migration by SQL, returns the procedure id if success.
async fn trigger_migration_by_sql(
    cluster: &GreptimeDbCluster,
    region_id: u64,
    from_peer_id: u64,
    to_peer_id: u64,
) -> String {
    let Output::Stream(stream, _) = run_sql(
        &cluster.frontend,
        &format!("select migrate_region({region_id}, {from_peer_id}, {to_peer_id})"),
        QueryContext::arc(),
    )
    .await
    .unwrap() else {
        unreachable!();
    };

    let recordbatches = RecordBatches::try_collect(stream).await.unwrap();

    info!("SQL result:\n {}", recordbatches.pretty_print().unwrap());

    let Value::String(procedure_id) = recordbatches.take()[0].column(0).get(0) else {
        unreachable!();
    };

    procedure_id.as_utf8().to_string()
}

/// Query procedure state by SQL.
async fn query_procedure_by_sql(instance: &Arc<Instance>, pid: &str) -> String {
    let Output::Stream(stream, _) = run_sql(
        instance,
        &format!("select procedure_state('{pid}')"),
        QueryContext::arc(),
    )
    .await
    .unwrap() else {
        unreachable!();
    };

    let recordbatches = RecordBatches::try_collect(stream).await.unwrap();

    info!("SQL result:\n {}", recordbatches.pretty_print().unwrap());

    let Value::String(state) = recordbatches.take()[0].column(0).get(0) else {
        unreachable!();
    };

    state.as_utf8().to_string()
}

async fn insert_values(instance: &Arc<Instance>, ts: u64) -> Vec<FrontendResult<Output>> {
    let query_ctx = QueryContext::arc();

    let mut results = Vec::new();
    for range in [5, 15, 55] {
        let result = run_sql(
            instance,
            &format!("INSERT INTO {TEST_TABLE_NAME} VALUES ({},{})", range, ts),
            query_ctx.clone(),
        )
        .await;
        results.push(result);
    }

    results
}

async fn run_sql(
    instance: &Arc<Instance>,
    sql: &str,
    query_ctx: QueryContextRef,
) -> FrontendResult<Output> {
    info!("Run SQL: {sql}");
    instance.do_query(sql, query_ctx).await.remove(0)
}
