"""Generate clearly labeled synthetic files for the browser demo."""
from scripts.paths import FIXTURES
from scripts.scenarios import scenario, jsonl, conn_tsv


def main():
    directory = FIXTURES
    directory.mkdir(parents=True, exist_ok=True)
    records = scenario()
    for source, rows in records.items():
        (directory / f"synthetic-{source}.jsonl").write_bytes(jsonl(rows))
    (directory / "synthetic-conn.tsv").write_bytes(conn_tsv(records["zeek_conn"]))
    print(f"Generated synthetic lab fixtures in {directory}")


if __name__ == "__main__":
    main()
