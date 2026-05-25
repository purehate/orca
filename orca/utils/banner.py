"""ORCA ASCII whale banner with Odoo symbol in the blowhole spray."""

from rich.console import Console


BANNER_ART = r"""
                                    .' '.
                                  .'     '.
                                 /  o   o  \         .---.
                                |     ^     |      .'  o  '.
                                 \   '-'   /      /  o   o  \
                                  '. ___ .'      |   o   o   |
                                    | |          |  .-----.  |
                                    | |           \  'o o'  /
                                    | |            '._____.'
                                    | |               | |
              _____                | |               | |
         _.-~~     ~~-._           | |               | |
       .'               '.        | |               | |
      /   .--.     .--.   \      | |               | |
     /  .'    \   /    '.  \     | |               | |
    |  |  O    |_|    O  |  |    | |               | |
    |  |   \   / \   /   |  |____| |_______________| |___
     \  \   '-'   '-'   /  /    \ /                 \ /
      \  '.__       __.'  /      V                   V
       '-.   '-----'   .-'
          '-._     _.-'          ~  ~  ~  ~  ~  ~  ~  ~
              '---'           ~    ~    ~    ~    ~    ~
                           ~  ~  ~  ~  ~  ~  ~  ~  ~  ~  ~
"""


def print_banner(console: Console, version: str = "") -> None:
    """Print the ORCA banner to console."""
    lines = BANNER_ART.strip("\n").split("\n")

    for line in lines:
        if "~" in line:
            console.print(f"[blue]{line}[/blue]")
        else:
            # Color the spray dots
            styled = line.replace(".", "[cyan].[/cyan]")
            # Color the o characters in spray (Odoo symbol)
            styled = styled.replace("o", "[bold magenta]o[/bold magenta]")
            console.print(styled)

    console.print()
    ver = f"  v{version}" if version else ""
    console.print(f"[bold cyan]    ORCA[/bold cyan] — [bold white]Odoo Recon & Configuration Analyzer[/bold white][dim]{ver}[/dim]")
    console.print("[dim cyan]    https://github.com/purehate/orca[/dim cyan]")
    console.print()
