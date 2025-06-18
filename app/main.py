import argparse
import logging

from app.core.args import init_args
from app.core.constants import APP_NAME
from app.core.runner import run_tool
from app.models.scan_config import ScanConfig
from app.utils.logging_utils import setup_logging
from app.utils.system_utils import get_raw_cli_args, is_frozen


async def main():
    raw_args = await get_raw_cli_args()

    # --- Determine Initial Application Mode ---
    if await is_frozen() and not raw_args:
        # Scenario 1: Frozen executable run with no command-line arguments (double-click)
        args: argparse.Namespace = await init_args()
        args.gui = True  # Force GUI mode if it's a binary click without arguments
    else:
        # Scenario 2: Command-line invocation (either with --gui or targets, or both)
        args: argparse.Namespace = await init_args()

    # --- Override GUI mode if targets are provided and --gui is not explicitly set ---
    if not args.gui and args.target:
        # If GUI is NOT requested AND targets ARE provided, it's CLI mode.
        pass
    elif not args.gui and not args.target and not await is_frozen():
        # Scenario 3: Python script run with no arguments (e.g., `python main.py`).
        # We'll also default this to GUI.
        args.gui = True

    # --- Initialize Logging ---
    log_level = "DEBUG" if args.verbose else "INFO"
    await setup_logging(log_level)
    logger = logging.getLogger(__name__)
    logger.info(f"Starting {APP_NAME}...")

    # --- ScanConfig from parsed arguments ---
    scan_config: ScanConfig = ScanConfig(
        target=args.target,
        verbose=args.verbose,
        ai_provider=args.ai_provider,
        ai_model=args.ai_model,
        ai_api_key=args.ai_api_key,
        ai_no_cache=args.ai_no_cache,
        ai_limit_nse=args.ai_limit_nse,
        disable_nuclei=args.disable_nuclei,
        disable_afrog=args.disable_afrog,
        report_format=args.report_format,
        report_base_dir=args.report_base_dir,
        report_zip=args.report_zip,
        report_file=args.report_file,
    )

    # --- Launch Application Mode ---
    if args.gui:
        logger.info("Running in GUI mode.")
        # await run_gui(args)
    else:
        logger.info("Running in CLI mode (default).")

        await run_tool(scan_config=scan_config)

    logger.info(f"{APP_NAME} finished.")
