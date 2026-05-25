"""ORCA ASCII whale banner with Odoo symbol in the blowhole spray."""

from rich.console import Console


BANNER_ART = r"""
                .--.   .--.   .--.   .--.
                ( oo ) ( dd ) ( oo ) ( oo )
                 '--'   '--'   '--'   '--'
                        .'  .  '.
                      .'  ,',.  '.
                     ; .'  ;;  '. ;
                      '    ;;    '
                           ;'
                           ;

                            :._   _.------------.___
                    __      :__:-'                  '--.
             __   ,' .'    .'             ______________'.
           /__ '.-  _\___.'          0  .' .'  .'  _.-_.'
              '._                     .-': .' _.' _.'_.'
                '----'._____________.'_'._:_:_.-'--'
"""


def print_banner(console: Console, version: str = "") -> None:
    """Print the ORCA banner to console."""
    lines = BANNER_ART.strip("\n").split("\n")

    for line in lines:
        if "~" in line:
            console.print(f"[blue]{line}[/blue]")
        elif "'" in line or ";" in line or ":" in line or "." in line:
            # Color the spray dots and spray shape
            styled = line.replace(".", "[cyan].[/cyan]")
            styled = styled.replace(";", "[cyan];[/cyan]")
            styled = styled.replace(":", "[cyan]:[/cyan]")
            styled = styled.replace("'", "[cyan]'[/cyan]")
            styled = styled.replace(",", "[cyan],[/cyan]")
            console.print(styled)
        else:
            console.print(line)

    console.print()
    ver = f"  v{version}" if version else ""
    console.print(f"[bold cyan]    ORCA[/bold cyan] — [bold white]Odoo Recon & Configuration Analyzer[/bold white][dim]{ver}[/dim]")
    console.print("[dim cyan]    https://github.com/purehate/orca[/dim cyan]")
    console.print()
