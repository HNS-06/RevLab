"""
Serve CLI Command Module
"""
import typer
from .theme import console, print_banner, print_header, COLOR_CYAN, COLOR_BRAND
from ..server.api import start_server, HAS_FASTAPI

app = typer.Typer(help="Launch RevLab headless REST API server.")

@app.callback(invoke_without_command=True)
def run_serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port number")
):
    """Launches FastAPI REST server for automated remote binary analysis pipelines."""
    print_banner()
    print_header("Headless REST API Server", f"http://{host}:{port}")

    if not HAS_FASTAPI:
        console.print("[bold red]x FastAPI and Uvicorn are required for REST API server.[/]")
        console.print("[dim]Install via: pip install fastapi uvicorn[/]")
        return

    console.print(f"✔ API documentation swagger available at: [bold cyan]http://{host}:{port}/docs[/]")
    console.print(f"✔ Health check endpoint: [bold cyan]http://{host}:{port}/api/v1/health[/]\n")

    start_server(host=host, port=port)
