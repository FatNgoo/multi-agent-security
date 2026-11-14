"""Generate clearly labeled synthetic files for the browser demo."""
from pathlib import Path
from evaluation.scenarios import scenario, jsonl, conn_tsv


def main():
    directory = Path(__file__).resolve().parents[1] / "data" / "fixtures"
    directory.mkdir(parents=True, exist_ok=True)
    records = scenario()
    for source, rows in records.items():
        (directory / f"synthetic-{source}.jsonl").write_bytes(jsonl(rows))
    (directory / "synthetic-conn.tsv").write_bytes(conn_tsv(records["zeek_conn"]))
    print("Generated synthetic lab fixtures in data/fixtures")


if __name__ == "__main__":
    main()
