import os
import csv
import argparse
import datetime
from falconpy import Detects


def connect():
    """Create a Detects service object using environment variables."""
    cid = os.getenv("FALCON_CLIENT_ID")
    secret = os.getenv("FALCON_CLIENT_SECRET")
    cloud = os.getenv("FALCON_CLOUD", "us-1")  # Default to US‑1

    if not cid or not secret:
        raise SystemExit("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET env vars.")

    # base_url example: https://us-1.crowdstrike.com
    base_url = f"https://{cloud}.crowdstrike.com"
    return Detects(client_id=cid, client_secret=secret, base_url=base_url)


def fetch_latest(detects, limit):
    """Retrieve summaries for the most recent <limit> detections."""
    query = detects.query_detections(parameters={"limit": limit})
    ids = query.get("body", {}).get("resources", [])

    if not ids:
        return []

    detail_resp = detects.get_detect_summaries(ids=ids)
    return detail_resp.get("body", {}).get("resources", [])


def export_csv(detections, outfile):
    """Write the detection list to CSV (UTC timestamps)."""
    if not detections:
        print("No detections to export.")
        return

    header = [
        "device_name",
        "severity",
        "status",
        "behavior_id",
        "behavior_description",
        "timestamp_utc",
    ]

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()

        for det in detections:
            writer.writerow({
                "device_name": det["device"]["device_name"],
                "severity": det["severity"],
                "status": det["status"],
                "behavior_id": det["behavior_id"],
                "behavior_description": det["behavior_description"],
                "timestamp_utc": datetime.datetime.utcfromtimestamp(det["timestamp"] / 1000).isoformat()
            })

    print(f"Exported {len(detections)} detections to {outfile}.")


def main():
    parser = argparse.ArgumentParser(description="Export recent CrowdStrike detections to CSV using FalconPy")
    parser.add_argument("--limit", type=int, default=10, help="Number of detections to fetch (default 10)")
    parser.add_argument("--outfile", default="detections.csv", help="CSV output filename")
    args = parser.parse_args()

    detects = connect()
    dets = fetch_latest(detects, args.limit)
    export_csv(dets, args.outfile)


if __name__ == "__main__":
    main()
