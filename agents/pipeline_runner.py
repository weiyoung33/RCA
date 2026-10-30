"""Run batch import and incident analysis from one process."""

from __future__ import annotations

import argparse
import logging
import os
import time

if __package__:
    from .batch_importer import BatchImporter, BatchImporterSettings
    from .orchestrator import process_incident
else:
    from batch_importer import BatchImporter, BatchImporterSettings
    from orchestrator import process_incident


LOGGER = logging.getLogger("rca.pipeline_runner")
ACTIVE_SLEEP_SECONDS = int(
    os.getenv("PIPELINE_RUNNER_ACTIVE_SLEEP_SECONDS", "2")
)


def run_cycle(importer: BatchImporter) -> tuple[int, bool]:
    """Import eligible batches, then process at most one NEW incident."""

    inserted = importer.import_new_batches()
    processed = process_incident()
    return inserted, processed


def run_pipeline(*, once: bool = False) -> None:
    """Run one combined cycle or continuously poll both pipeline stages."""

    settings = BatchImporterSettings.from_environment()
    if ACTIVE_SLEEP_SECONDS < 0:
        raise RuntimeError(
            "PIPELINE_RUNNER_ACTIVE_SLEEP_SECONDS cannot be negative"
        )

    importer = BatchImporter(settings)

    if once:
        inserted, processed = run_cycle(importer)
        LOGGER.info(
            "Combined cycle completed; imported=%d processed=%s",
            inserted,
            processed,
        )
        return

    LOGGER.info(
        "Combined pipeline runner started; import_limit=%d idle_poll=%ds",
        settings.batch_size,
        settings.poll_seconds,
    )
    while True:
        try:
            inserted, processed = run_cycle(importer)
            if inserted or processed:
                LOGGER.info(
                    "Combined cycle completed; imported=%d processed=%s",
                    inserted,
                    processed,
                )
        except Exception:
            LOGGER.exception("Combined pipeline cycle failed")
            inserted = 0
            processed = False

        time.sleep(
            ACTIVE_SLEEP_SECONDS
            if inserted or processed
            else settings.poll_seconds
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import replicated batches and run the RCA pipeline from one process"
        )
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one import cycle, process at most one incident, and exit",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run_pipeline(once=args.once)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        LOGGER.info("Combined pipeline runner shut down manually")
