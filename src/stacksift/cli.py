import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from time import perf_counter

from stacksift.analyzer import analyze_path
from stacksift.reports import save_report

from stacksift.insights import (
    determine_health,
    most_frequent_issue,
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

def display_incident_summary(results: dict) -> None:
    health, health_style = determine_health(results["level_counts"])
    frequent_issue = most_frequent_issue(results["issues"])

    files_scanned = len(results.get("scanned_files", [results["file"]]))
    critical_count = results["level_counts"].get("CRITICAL", 0)
    error_count = results["level_counts"].get("ERROR", 0)
    warning_count = results["level_counts"].get("WARN", 0)

    summary = Text()

    summary.append("Health: ")
    summary.append(health, style=f"bold {health_style}")
    summary.append("\n\n")

    summary.append(f"Files scanned:     {files_scanned}\n")
    summary.append(f"Lines parsed:      {results['parsed_lines']}\n")
    summary.append(f"Malformed lines:   {results['malformed_lines']}\n")
    summary.append(f"Critical entries:  {critical_count}\n")
    summary.append(f"Error entries:     {error_count}\n")
    summary.append(f"Warning entries:   {warning_count}\n")

    if frequent_issue:
        message, issue_data = frequent_issue
        summary.append("\nMost frequent issue:\n", style="bold")
        summary.append(message)
        summary.append(f"\nOccurred {issue_data['count']} time(s)")

    console.print(
        Panel(
            summary,
            title="Incident Summary",
            border_style=health_style,
        )
    )

@app.command()
def analyze(file_path: str):
    """Analyze a log file or folder of log files."""
    start_time = perf_counter()
    results = analyze_path(file_path)
    elapsed_time = perf_counter() - start_time
    display_incident_summary(results)

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