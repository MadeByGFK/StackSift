import typer
from rich.console import Console
from rich.table import Table

from time import perf_counter

from stacksift.analyzer import analyze_path
from stacksift.reports import save_report
from stacksift.insights import (
    sort_issues_by_severity,
)

app = typer.Typer()
console = Console()

LEVEL_STYLES = {
    "INFO": "green",
    "WARN": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}

@app.command()
def analyze(file_path: str):
    """Analyze a log file or folder of log files."""
    start_time = perf_counter()
    results = analyze_path(file_path)
    elapsed_time = perf_counter() - start_time

    console.print("\n[bold]StackSift Summary[/bold]\n")
    console.print(f"[bold]File:[/bold] {results['file']}")
    console.print(f"[bold]Total lines:[/bold] {results['total_lines']}")
    console.print(f"[bold]Parsed lines:[/bold] {results['parsed_lines']}\n")
    console.print(f"[bold]Malformed lines:[/bold] {results['malformed_lines']}\n")
    console.print(f"[bold]Scan time:[/bold] {elapsed_time:.3f}s\n")

    if "scanned_files" in results:
        console.print(f"[bold]Files scanned:[/bold] {len(results['scanned_files'])}")

        for scanned_file in results["scanned_files"]:
            console.print(f"  [green]✓[/green] {scanned_file}")

        console.print()

    table = Table(title="Log Levels")
    table.add_column("Level")
    table.add_column("Count")

    for level, count in results["level_counts"].items():
        style = LEVEL_STYLES.get(level, "white")
        table.add_row(f"[{style}]{level}[/{style}]", str(count))

    console.print(table)

    if results["issues"]:
        issue_table = Table(title="Issues")
        issue_table.add_column("Level")
        issue_table.add_column("Issue")
        issue_table.add_column("Count")

        sorted_issues = sort_issues_by_severity(results["issues"])

        for issue, data in sorted_issues:
            style = LEVEL_STYLES.get(data["level"], "white")
            issue_table.add_row(
                f"[{style}]{data['level']}[/{style}]",
                issue,
                str(data["count"]),
            )

        console.print(issue_table)

    report_path = save_report(results)
    console.print(f"\n[green]Report saved to:[/green] {report_path}")

if __name__ == "__main__":
    app()