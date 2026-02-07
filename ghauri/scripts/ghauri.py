#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghauri – modernized main CLI entry point (2026 edition)

Features:
• Typer-based CLI (type hints, rich help, validation)
• Grouped options (Target, Request, Detection, Enumeration, etc.)
• Rich console output (tables, progress, colors)
• Backward compatible flags
• Better error handling & user experience

Install extras if you want rich output:
    pip install typer rich
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from ghauri import __version__, banner
from ghauri.common.config import conf, GhauriConfig
from ghauri.common.utils import dbms_full_name
from ghauri.logger.colored_logger import logger, set_level
from ghauri.core import perform_injection, perform_multitarget_injection
from ghauri import Ghauri

app = typer.Typer(
    name="ghauri",
    help="Advanced SQL injection detection & exploitation tool",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]Ghauri[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show version and exit"
    ),
    verbose: int = typer.Option(1, "-v", "--verbose", min=0, max=5, help="Verbosity level (0-5)"),
    batch: bool = typer.Option(False, "--batch", help="Never ask for input, use defaults"),
):
    set_level(verbose)
    conf.batch = batch
    conf.verbose = verbose


# ─── Target group ───────────────────────────────────────────────────────────────────

target_group = typer.OptionGroup("Target")


@target_group.option(
    "-u", "--url", type=str, help="Target URL (e.g. http://example.com/vuln.php?id=1)"
)
@target_group.option(
    "-m", "--bulkfile", type=Path, help="Scan multiple targets from a file"
)
@target_group.option(
    "-r", "--requestfile", type=Path, help="Load HTTP request from file (Burp/ZAP format)"
)
def target_options(
    url: Optional[str] = None,
    bulkfile: Optional[Path] = None,
    requestfile: Optional[Path] = None,
):
    if not any([url, bulkfile, requestfile]):
        console.print("[red]Error:[/] At least one target option (-u, -m, -r) is required.")
        raise typer.Exit(1)


# ─── Request group ──────────────────────────────────────────────────────────────────

request_group = typer.OptionGroup("Request")


@request_group.option("--data", type=str, help="POST data string (e.g. id=1&name=test)")
@request_group.option("--cookie", type=str, help="HTTP Cookie header")
@request_group.option("--header", type=str, help="Extra header (e.g. X-Forwarded-For: 127.0.0.1)")
@request_group.option("--user-agent", type=str, help="Custom User-Agent")
@request_group.option("--host", type=str, help="Custom Host header")
@request_group.option("--referer", type=str, help="Custom Referer header")
@request_group.option("--mobile", is_flag=True, help="Imitate mobile User-Agent")
@request_group.option("--random-agent", is_flag=True, help="Random User-Agent")
@request_group.option("--proxy", type=str, help="Proxy URL (e.g. http://127.0.0.1:8080)")
@request_group.option("--force-ssl", is_flag=True, help="Force HTTPS")
@request_group.option("--timeout", type=float, default=30.0, help="Request timeout (seconds)")
@request_group.option("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
@request_group.option("--timesec", type=float, default=5.0, help="Time-based delay threshold")
def request_options(**kwargs):
    for k, v in kwargs.items():
        if v is not None:
            setattr(conf, k.replace("-", "_"), v)


# ─── Detection & Technique group ────────────────────────────────────────────────────

detection_group = typer.OptionGroup("Detection & Techniques")


@detection_group.option(
    "--level", type=int, default=1, min=1, max=5, help="Detection level (1-5)"
)
@detection_group.option(
    "--tech", type=str, default="BEISTQU", help="Techniques to test (B)oolean, (E)rror, (I)nline, (S)tacked, (T)ime, (Q)uarantine, (U)nion"
)
@detection_group.option(
    "--test-filter", type=str, help="Filter tests by title (comma-separated)"
)
@detection_group.option(
    "--fetch-using", type=str, help="Fetch method: binary, between, in, equal"
)
@detection_group.option(
    "--tamper", type=str, help="Comma-separated tampers or 'all' (e.g. charencode,space2comment)"
)
def detection_options(**kwargs):
    for k, v in kwargs.items():
        if v is not None:
            setattr(conf, k.replace("-", "_"), v)


# ─── Enumeration group ──────────────────────────────────────────────────────────────

enum_group = typer.OptionGroup("Enumeration")


@enum_group.option("--banner", is_flag=True, help="Get DBMS banner/version")
@enum_group.option("--current-user", is_flag=True, help="Get current user")
@enum_group.option("--current-db", is_flag=True, help="Get current database")
@enum_group.option("--hostname", is_flag=True, help="Get hostname")
@enum_group.option("--dbs", is_flag=True, help="Enumerate databases")
@enum_group.option("--tables", is_flag=True, help="Enumerate tables (requires --db)")
@enum_group.option("--columns", is_flag=True, help="Enumerate columns (requires --db --tbl)")
@enum_group.option("--dump", is_flag=True, help="Dump table data (requires --db --tbl)")
@enum_group.option("--db", type=str, help="Specific database to target")
@enum_group.option("--tbl", type=str, help="Specific table to target")
@enum_group.option("--cols", type=str, help="Comma-separated columns to dump")
@enum_group.option("--count-only", is_flag=True, help="Only count rows (no dump)")
@enum_group.option("--limit-start", type=int, default=0, help="Start row for dump")
@enum_group.option("--limit-stop", type=int, default=0, help="Stop row for dump")
def enum_options(**kwargs):
    for k, v in kwargs.items():
        if v is not None:
            setattr(conf, k.replace("-", "_"), v)


# ─── Misc / Advanced group ──────────────────────────────────────────────────────────

misc_group = typer.OptionGroup("Miscellaneous")


@misc_group.option("--batch", is_flag=True, help="Non-interactive mode")
@misc_group.option("--flush-session", is_flag=True, help="Clear session files")
@misc_group.option("--fresh-queries", is_flag=True, help="Ignore cached results")
@misc_group.option("--threads", type=int, default=1, help="Number of threads")
@misc_group.option("--sql-shell", is_flag=True, help="Interactive SQL shell (experimental)")
@misc_group.option("--update", is_flag=True, help="Check for updates")
@misc_group.option("--ignore-code", type=str, help="Ignore HTTP status codes (comma or *)")
def misc_options(**kwargs):
    for k, v in kwargs.items():
        if v is not None:
            setattr(conf, k.replace("-", "_"), v)


@app.command()
def run(
    # Target (required via group)
    url: Optional[str] = None,
    bulkfile: Optional[Path] = None,
    requestfile: Optional[Path] = None,

    # Request
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    header: Optional[str] = None,
    user_agent: Optional[str] = None,
    host: Optional[str] = None,
    referer: Optional[str] = None,
    mobile: bool = False,
    random_agent: bool = False,
    proxy: Optional[str] = None,
    force_ssl: bool = False,
    timeout: float = 30.0,
    delay: float = 0.0,
    timesec: float = 5.0,

    # Detection
    level: int = 1,
    tech: str = "BEISTQU",
    test_filter: Optional[str] = None,
    fetch_using: Optional[str] = None,
    tamper: Optional[str] = None,

    # Enumeration
    banner: bool = False,
    current_user: bool = False,
    current_db: bool = False,
    hostname: bool = False,
    dbs: bool = False,
    tables: bool = False,
    columns: bool = False,
    dump: bool = False,
    db: Optional[str] = None,
    tbl: Optional[str] = None,
    cols: Optional[str] = None,
    count_only: bool = False,
    limit_start: int = 0,
    limit_stop: int = 0,

    # Misc
    batch: bool = False,
    flush_session: bool = False,
    fresh_queries: bool = False,
    threads: int = 1,
    sql_shell: bool = False,
    update: bool = False,
    ignore_code: Optional[str] = None,
):
    """Run Ghauri SQL injection scan/exploitation"""

    # Update conf from CLI
    conf.level = level
    conf.tech = tech
    conf.test_filter = test_filter
    conf.fetch_using = fetch_using
    conf.tamper = tamper
    conf.banner = banner
    # ... assign other flags similarly ...

    if update:
        # Implement update check logic here (e.g. compare __version__ vs GitHub API)
        logger.info("Update check not implemented yet in this version.")
        raise typer.Exit()

    if bulkfile:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
        ) as progress:
            progress.add_task(description="Scanning multiple targets...", total=None)
            perform_multitarget_injection(args=conf)
    else:
        resp = perform_injection(args=conf)

        if not resp.is_injected:
            logger.error("No injectable parameter found.")
            raise typer.Exit(1)

        target = Ghauri(
            url=resp.url,
            data=resp.data,
            vector=resp.vector,
            backend=resp.backend,
            parameter=resp.parameter,
            headers=resp.headers,
            base=resp.base,
            injection_type=resp.injection_type,
            proxy=resp.proxy,
            filepaths=resp.filepaths,
            is_multipart=resp.is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack=resp.attack,
            match_string=resp.match_string,
            vectors=resp.vectors,
        )

        # Enumeration phase
        if banner:
            target.extract_banner()
        if current_user:
            target.extract_current_user()
        if current_db:
            current_db_result = target.extract_current_db()
            current_db = current_db_result.result.strip() if current_db_result.ok else None
        if hostname:
            target.extract_hostname()
        if dbs:
            target.extract_dbs(start=limit_start, stop=limit_stop)
        if db and tables:
            target.extract_tables(database=db, start=limit_start, stop=limit_stop)
        if db and tbl and columns:
            target.extract_columns(database=db, table=tbl, start=limit_start, stop=limit_stop)
        if db and tbl and count_only:
            target.extract_records(
                database=db, table=tbl, columns="", start=limit_start, stop=limit_stop, count_only=True
            )
        if db and tbl and cols and dump:
            target.extract_records(
                database=db, table=tbl, columns=cols, start=limit_start, stop=limit_stop
            )
        if db and dump and not tbl and not cols:
            target.dump_database(database=db, start=limit_start, stop=limit_stop, dump_requested=True)
        if db and tbl and dump and not cols:
            target.dump_table(database=db, table=tbl, start=limit_start, stop=limit_stop, dump_requested=True)
        if dump and not db and not tbl and not cols:
            target.dump_current_db(current_db=current_db, dump_requested=True)

        logger.success("Scan completed.")
        target._end()


if __name__ == "__main__":
    banner.print_banner()  # assuming you have a banner module
    app()
