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
const MIGRATIONS: &[Migration] = &[
    Migration {
        from_version: 0,
        sql: include_str!("migrations/0001_initial_schema.sql"),
    },
    Migration {
        from_version: 1,
        sql: include_str!("migrations/0002_foreign_key_indexes.sql"),
    },
    Migration {
        from_version: 2,
        sql: include_str!("migrations/0003_contact_external_id.sql"),
    },
    Migration {
        from_version: 3,
        sql: include_str!("migrations/0004_pending_object_deletions.sql"),
    },
];

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

        apply_one(conn, migration)?;
        version += 1;
    }

    Ok(())
}

/// Apply a single migration step inside one SQL transaction: run its SQL, bump
/// `user_version`, then commit. If any part fails, the transaction rolls back automatically
/// (it is never committed) so `user_version` is left exactly where it was and none of the
/// migration's schema changes are visible - a crash or forced interruption at any point during
/// this function can only ever be observed as "the migration did not happen yet", never as a
/// database stuck between two schema versions.
fn apply_one(conn: &mut Connection, migration: &Migration) -> Result<(), StorageError> {
    let next = migration.from_version + 1;
    let failed = || StorageError::MigrationFailed { version: next };

    let tx = conn.transaction().map_err(|_| failed())?;
    tx.execute_batch(migration.sql).map_err(|_| failed())?;
    tx.pragma_update(None, "user_version", next)
        .map_err(|_| failed())?;
    tx.commit().map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_migration_step_leaves_user_version_and_schema_untouched() {
        let mut conn = Connection::open_in_memory().expect("open in-memory db");
        let broken = Migration {
            from_version: 0,
            // Deliberately invalid: no such table. execute_batch must fail partway through,
            // and the CREATE TABLE before it must not survive the transaction rollback.
            sql: "CREATE TABLE should_not_persist (id INTEGER); \
                  INSERT INTO this_table_does_not_exist (id) VALUES (1);",
        };

        let error = apply_one(&mut conn, &broken).expect_err("broken migration must fail");
        assert!(matches!(
            error,
            StorageError::MigrationFailed { version: 1 }
        ));

        let version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .expect("read user_version");
        assert_eq!(
            version, 0,
            "a failed migration transaction must not advance user_version"
        );

        let table_exists: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'should_not_persist';",
                [],
                |row| row.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(
            table_exists, 0,
            "a failed migration transaction must not partially apply its schema changes"
        );
    }

    #[test]
    fn migrate_to_latest_is_a_no_op_once_already_current() {
        let mut conn = Connection::open_in_memory().expect("open in-memory db");
        migrate_to_latest(&mut conn, 2).expect("migrate to latest");
        // Calling it again at the same target must not error or re-run migrations (which
        // would fail loudly, e.g. "table already exists", if it tried).
        migrate_to_latest(&mut conn, 2).expect("migrating an already-current db is a no-op");
    }
}
