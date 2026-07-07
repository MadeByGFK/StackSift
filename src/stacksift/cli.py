import typer
from rich.console import Console
from rich.table import Table

from stacksift.analyzer import analyze_log_file, save_report

app = typer.Typer()
console = Console()


@app.command()
def analyze(file_path: str):
    """Analyze a log file and print a summary."""
    results = analyze_log_file(file_path)

    console.print("\n[bold]StackSift Summary[/bold]\n")
    console.print(f"[bold]File:[/bold] {results['file']}")
    console.print(f"[bold]Total lines:[/bold] {results['total_lines']}")
    console.print(f"[bold]Parsed lines:[/bold] {results['parsed_lines']}\n")

    table = Table(title="Log Levels")
    table.add_column("Level")
    table.add_column("Count")

    for level, count in results["level_counts"].items():
        table.add_row(level, str(count))

    console.print(table)

    if results["top_issues"]:
        issue_table = Table(title="Top Issues")
        issue_table.add_column("Issue")
        issue_table.add_column("Count")

        for issue, count in results["top_issues"]:
            issue_table.add_row(issue, str(count))

        console.print(issue_table)

    report_path = save_report(results)
    console.print(f"\n[green]Report saved to:[/green] {report_path}")

if __name__ == "__main__":
    app()