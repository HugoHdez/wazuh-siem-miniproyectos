import argparse
import sys
import time
from pathlib import Path


DEFAULT_SOURCE = Path(
    "./single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog_full.log"
)
DEFAULT_TARGET = Path(
    "./single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog.log"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replay generated WannaCry syslog events into the file monitored by Wazuh."
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument(
        "--delay",
        type=float,
        default=0.02,
        help="Seconds to wait after each batch. Use 0 for fastest replay.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Number of log lines appended before sleeping.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Truncate the target log before replaying.",
    )
    parser.add_argument(
        "--reset-only",
        action="store_true",
        help="Truncate the target log and exit without replaying events.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of lines to replay. 0 means all lines.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1000,
        help="Print progress every N lines. 0 disables progress output.",
    )
    return parser.parse_args()


def replay(source, target, delay, batch_size, reset, reset_only, limit, progress_every):
    if batch_size < 1:
        raise ValueError("--batch-size must be >= 1")
    if delay < 0:
        raise ValueError("--delay must be >= 0")
    if limit < 0:
        raise ValueError("--limit must be >= 0")
    target.parent.mkdir(parents=True, exist_ok=True)

    if reset_only:
        target.write_text("", encoding="utf-8", newline="\n")
        print(f"[OK] Target log reset: {target}")
        return

    if not source.exists():
        raise FileNotFoundError(f"Source log not found: {source}")

    mode = "w" if reset else "a"

    sent = 0
    batch_count = 0
    with source.open("r", encoding="utf-8") as src, target.open(
        mode, encoding="utf-8", newline="\n"
    ) as dst:
        for line in src:
            dst.write(line)
            sent += 1
            batch_count += 1

            if batch_count >= batch_size:
                dst.flush()
                batch_count = 0
                if delay:
                    time.sleep(delay)

            if progress_every and sent % progress_every == 0:
                print(f"[OK] Replayed {sent} events into {target}", flush=True)

            if limit and sent >= limit:
                break

        dst.flush()

    print(f"[OK] Replay finished. Events sent: {sent}")


def main():
    args = parse_args()
    try:
        replay(
            source=args.source,
            target=args.target,
            delay=args.delay,
            batch_size=args.batch_size,
            reset=args.reset,
            reset_only=args.reset_only,
            limit=args.limit,
            progress_every=args.progress_every,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Replay interrupted by user.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
