"""CLI entry point: thin wrapper over core.py (see PLAN.md 8)."""

import click


@click.group()
def main(): ...


@main.command()
@click.option("--target-module", default=None)
@click.option("--target-url", default=None)
@click.option("--patterns", multiple=True)
@click.option("--min-score", default=0.0, type=float)
@click.option("--output", type=click.Choice(["text", "json"]), default="text")
def run(target_module, target_url, patterns, min_score, output):
    """Run the default (plus any --patterns) attack patterns against a target.

    Exit codes: 0 = passed (score >= --min-score); 1 = score below
    --min-score; 2 = target unreachable / configuration error.
    """
    raise NotImplementedError


if __name__ == "__main__":
    main()
