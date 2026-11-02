"""Run explicit source synchronizations without starting the web server."""

import argparse
import logging
import os

from database import CVEDatabase
from nvd_client import CISAKEVUpdateError, NVDClient, NVDUpdateError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sync_group = parser.add_mutually_exclusive_group(required=True)
    sync_group.add_argument(
        "--nvd-full",
        action="store_true",
        help="Page through the full NVD CVE catalog to seed the local database.",
    )
    sync_group.add_argument(
        "--nvd-recent",
        action="store_true",
        help="Sync CVEs modified during the requested recent window.",
    )
    sync_group.add_argument(
        "--cisa-kev",
        action="store_true",
        help="Mirror the CISA Known Exploited Vulnerabilities catalog.",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=1,
        help="Modified-date window for --nvd-recent (1-120 days; default: 1).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    db = CVEDatabase()
    client = NVDClient(
        api_key=os.environ.get("NVD_API_KEY"),
        github_token=os.environ.get("GITHUB_TOKEN"),
    )

    try:
        if args.nvd_full:
            count = client.sync_nvd_full(db)
            source = "NVD full catalog"
        elif args.nvd_recent:
            count = client.update_recent_cves(db, days_back=args.days_back)
            source = "NVD recent updates"
        else:
            count = client.sync_cisa_kev(db)
            source = "CISA KEV"
    except (NVDUpdateError, CISAKEVUpdateError, ValueError) as exc:
        logging.getLogger(__name__).error("%s synchronization failed: %s", source_name(args), exc)
        return 1

    print(f"{source}: processed {count} records.")
    return 0


def source_name(args: argparse.Namespace) -> str:
    if args.nvd_full:
        return "NVD full catalog"
    if args.nvd_recent:
        return "NVD recent updates"
    return "CISA KEV"


if __name__ == "__main__":
    raise SystemExit(main())
