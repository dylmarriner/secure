//! Vault schema migrations.
//!
//! Schema state is tracked with SQLite's built-in `PRAGMA user_version`. Every migration is
//! an explicit, ordered, additive SQL step; there is no support for skipping versions or for
//! opening a vault whose stored version is newer than this build understands, since silently
//! "migrating forward" from an unknown future schema would risk corrupting data this build
//! cannot correctly interpret.

use rusqlite::Connection;

use crate::StorageError;

/// One migration step, applied when the database's current `user_version` equals
/// `from_version`. Each entry must leave the database at `from_version + 1`.
struct Migration {
    from_version: i64,
    sql: &'static str,
}

/// Ordered list of all known migrations. Append new entries here; never edit a migration that
/// has shipped, since existing vaults may already be at that version.
const MIGRATIONS: &[Migration] = &[Migration {
    from_version: 0,
    sql: include_str!("migrations/0001_initial_schema.sql"),
}];

pub(crate) fn migrate_to_latest(
    conn: &mut Connection,
    supported_version: i64,
) -> Result<(), StorageError> {
    let current: i64 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;

    if current > supported_version {
        return Err(StorageError::SchemaTooNew {
            found: current,
            supported: supported_version,
        });
    }

    let mut version = current;
    while version < supported_version {
        let migration = MIGRATIONS
            .iter()
            .find(|migration| migration.from_version == version)
            .ok_or(StorageError::MigrationFailed {
                version: version + 1,
            })?;

        let tx = conn
            .transaction()
            .map_err(|_| StorageError::MigrationFailed {
                version: version + 1,
            })?;
        tx.execute_batch(migration.sql)
            .map_err(|_| StorageError::MigrationFailed {
                version: version + 1,
            })?;
        let next = version + 1;
        tx.pragma_update(None, "user_version", next)
            .map_err(|_| StorageError::MigrationFailed { version: next })?;
        tx.commit().map_err(|_| StorageError::MigrationFailed {
            version: version + 1,
        })?;

        version = next;
    }

    Ok(())
}
