#!/usr/bin/env python3
"""Migrate aggregator commit_verification_records between Postgres databases."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from typing import Any, Iterable

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    print("ERROR: missing psycopg3 driver. Install it with: python3 -m pip install 'psycopg[binary]'", file=sys.stderr)
    raise SystemExit(2)


DEFAULT_COPY_BATCHES = 50

COPY_BATCH_QUERY = """
    COPY (
        SELECT
            message_id,
            signer_identifier,
            aggregation_key,
            message_data,
            ccv_version,
            signature,
            message_ccv_addresses,
            message_executor_address,
            created_at
        FROM commit_verification_records
        WHERE id >= %s AND id <= %s
        ORDER BY id
    ) TO STDOUT WITH (FORMAT csv, NULL '\\N')
"""

COPY_IN_QUERY = """
    COPY migrated_commit_verification_records (
        message_id,
        signer_identifier,
        aggregation_key,
        message_data,
        ccv_version,
        signature,
        message_ccv_addresses,
        message_executor_address,
        created_at
    ) FROM STDIN WITH (FORMAT csv, NULL '\\N')
"""


@dataclass(frozen=True)
class MigrationStats:
    staged_count: int
    inserted_count: int
    skipped_unique_verification_count: int
    present_after_count: int


@dataclass(frozen=True)
class SourceStats:
    row_count: int
    min_id: int | None
    max_id: int | None


@dataclass(frozen=True)
class CopyBatch:
    index: int
    start_id: int
    end_id: int
    path: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate aggregator commit_verification_records from one Postgres DB to another."
    )
    parser.add_argument(
        "--source-url",
        default=os.environ.get("SOURCE_DATABASE_URL", ""),
        help="source Postgres URL. Defaults to SOURCE_DATABASE_URL.",
    )
    parser.add_argument(
        "--dest-url",
        default=os.environ.get("DEST_DATABASE_URL", ""),
        help="destination Postgres URL. Defaults to DEST_DATABASE_URL.",
    )
    parser.add_argument(
        "--copy-batches",
        type=int,
        default=DEFAULT_COPY_BATCHES,
        help=f"number of ID-range COPY files to create. Default: {DEFAULT_COPY_BATCHES}.",
    )
    parser.add_argument(
        "--preserve-created-at",
        action="store_true",
        help=(
            "copy source created_at. By default migrated rows get NOW() so orphan recovery "
            "can see them under orphanRecovery.maxAge."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="scan and count source rows, but do not insert into destination.",
    )

    args = parser.parse_args()
    if not args.source_url:
        parser.error("--source-url or SOURCE_DATABASE_URL is required")
    if not args.dest_url:
        parser.error("--dest-url or DEST_DATABASE_URL is required")
    if args.copy_batches <= 0:
        parser.error("--copy-batches must be greater than 0")
    return args


def connect(url: str) -> Any:
    return psycopg.connect(url, row_factory=dict_row)


def execute(conn: Any, query: str, params: Iterable[Any] | None = None) -> None:
    with closing(conn.cursor()) as cur:
        cur.execute(query, tuple(params or ()))


def fetch_one(conn: Any, query: str, params: Iterable[Any] | None = None) -> Any:
    with closing(conn.cursor()) as cur:
        cur.execute(query, tuple(params or ()))
        return cur.fetchone()


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def get_source_stats(conn: Any) -> SourceStats:
    row = fetch_one(
        conn,
        "SELECT COUNT(*) AS row_count, MIN(id) AS min_id, MAX(id) AS max_id FROM commit_verification_records",
    )
    return SourceStats(
        row_count=int(row["row_count"]),
        min_id=None if row["min_id"] is None else int(row["min_id"]),
        max_id=None if row["max_id"] is None else int(row["max_id"]),
    )


def build_copy_batches(stats: SourceStats, batch_count: int, directory: str) -> list[CopyBatch]:
    if stats.row_count == 0 or stats.min_id is None or stats.max_id is None:
        return []

    id_span = stats.max_id - stats.min_id + 1
    range_size = max(1, (id_span + batch_count - 1) // batch_count)
    batches = []

    for index in range(batch_count):
        start_id = stats.min_id + index * range_size
        if start_id > stats.max_id:
            break
        end_id = min(stats.max_id, start_id + range_size - 1)
        path = os.path.join(directory, f"commit_verification_records_{index + 1:03d}.csv")
        batches.append(CopyBatch(index=index + 1, start_id=start_id, end_id=end_id, path=path))

    return batches


def create_temp_tables(conn: Any) -> None:
    execute(
        conn,
        """
        CREATE TEMP TABLE migrated_commit_verification_records (
            message_id TEXT NOT NULL,
            signer_identifier TEXT NOT NULL,
            aggregation_key TEXT NOT NULL,
            message_data JSONB NOT NULL,
            ccv_version BYTEA NOT NULL,
            signature BYTEA NOT NULL,
            message_ccv_addresses TEXT[] NOT NULL,
            message_executor_address TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        )
        """,
    )


def copy_source_batch_to_file(conn: Any, batch: CopyBatch) -> int:
    with open(batch.path, "wb") as file:
        with closing(conn.cursor()) as cur:
            with cur.copy(COPY_BATCH_QUERY, (batch.start_id, batch.end_id)) as copy:
                for data in copy:
                    if isinstance(data, str):
                        data = data.encode()
                    file.write(data)
    return os.path.getsize(batch.path)


def copy_file_to_dest(conn: Any, path: str) -> None:
    with open(path, "rb") as file:
        with closing(conn.cursor()) as cur:
            with cur.copy(COPY_IN_QUERY) as copy:
                while True:
                    data = file.read(1024 * 1024)
                    if not data:
                        break
                    copy.write(data)


def insert_staged_records(conn: Any, preserve_created_at: bool) -> int:
    created_at_expr = "created_at" if preserve_created_at else "NOW()"
    execute(conn, "ANALYZE migrated_commit_verification_records")

    query = f"""
        CREATE TEMP TABLE migrated_commit_verification_inserted AS
        WITH inserted AS (
            INSERT INTO commit_verification_records (
                message_id,
                signer_identifier,
                aggregation_key,
                message_data,
                ccv_version,
                signature,
                message_ccv_addresses,
                message_executor_address,
                created_at
            )
            SELECT
                message_id,
                signer_identifier,
                aggregation_key,
                message_data,
                ccv_version,
                signature,
                message_ccv_addresses,
                message_executor_address,
                {created_at_expr}
            FROM migrated_commit_verification_records
            ON CONFLICT (message_id, signer_identifier, aggregation_key) DO NOTHING
            RETURNING message_id, aggregation_key
        )
        SELECT message_id, aggregation_key
        FROM inserted
    """
    execute(conn, query)
    row = fetch_one(conn, "SELECT COUNT(*) FROM migrated_commit_verification_inserted")
    return int(row["count"])


def collect_stats(conn: Any) -> MigrationStats:
    query = """
        WITH counts AS (
            SELECT
                (SELECT COUNT(*) FROM migrated_commit_verification_records) AS staged_count,
                (SELECT COUNT(*) FROM migrated_commit_verification_inserted) AS inserted_count,
                (
                    SELECT COUNT(*)
                    FROM migrated_commit_verification_records staged
                    JOIN commit_verification_records dest
                        ON dest.message_id = staged.message_id
                        AND dest.signer_identifier = staged.signer_identifier
                        AND dest.aggregation_key = staged.aggregation_key
                ) AS present_after_count
        )
        SELECT
            staged_count,
            inserted_count,
            staged_count - inserted_count AS skipped_unique_verification_count,
            present_after_count
        FROM counts
    """
    row = fetch_one(conn, query)
    return MigrationStats(**row)


def migrate(args: argparse.Namespace) -> int:
    print("Using Postgres driver: psycopg3")
    with closing(connect(args.source_url)) as source_conn, closing(connect(args.dest_url)) as dest_conn:
        source_stats = get_source_stats(source_conn)
        print(
            f"Source rows: {source_stats.row_count} "
            f"min_id={source_stats.min_id} max_id={source_stats.max_id}"
        )

        if args.dry_run:
            print("Dry run requested; skipping destination insert.")
            return 0

        with tempfile.TemporaryDirectory(prefix="commit_verification_records_") as temp_dir:
            batches = build_copy_batches(source_stats, args.copy_batches, temp_dir)
            print(f"Exporting source rows with COPY into {len(batches)} local batch files...")
            copied_bytes = 0
            for batch in batches:
                batch_bytes = copy_source_batch_to_file(source_conn, batch)
                copied_bytes += batch_bytes
                print(
                    f"exported batch {batch.index}/{len(batches)} "
                    f"id_range={batch.start_id}-{batch.end_id} "
                    f"bytes={format_bytes(batch_bytes)} ({batch_bytes})"
                )
            print(
                f"Exported {source_stats.row_count} source rows into "
                f"{format_bytes(copied_bytes)} ({copied_bytes} bytes)"
            )

            create_temp_tables(dest_conn)
            print("Loading destination staging table with COPY from local batch files...")
            for batch in batches:
                batch_bytes = os.path.getsize(batch.path)
                if batch_bytes == 0:
                    print(f"skipped empty batch {batch.index}/{len(batches)}")
                    continue
                copy_file_to_dest(dest_conn, batch.path)
                print(
                    f"loaded batch {batch.index}/{len(batches)} "
                    f"bytes={format_bytes(batch_bytes)} ({batch_bytes})"
                )

            staged_count_row = fetch_one(dest_conn, "SELECT COUNT(*) FROM migrated_commit_verification_records")
            staged_count = staged_count_row["count"]
            print(f"Staged rows: {staged_count}")

            print("Inserting staged records into destination with ON CONFLICT DO NOTHING...")
            inserted = insert_staged_records(dest_conn, args.preserve_created_at)
            dest_conn.commit()
            print(
                "insert complete "
                f"inserted={inserted} skipped_unique_verification={int(staged_count) - inserted}"
            )

        stats = collect_stats(dest_conn)
        print("Migration result:")
        print(f"  staged rows: {stats.staged_count}")
        print(f"  inserted rows: {stats.inserted_count}")
        print(f"  skipped unique_verification rows: {stats.skipped_unique_verification_count}")
        print(f"  rows present after migration: {stats.present_after_count}")

    return 0


def main() -> int:
    args = parse_args()

    try:
        return migrate(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
