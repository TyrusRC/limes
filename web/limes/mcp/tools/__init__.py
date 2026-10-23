"""Tool modules. Each one registers its tools through limes.mcp.registry.tool; import them here so load_tools() sees them all."""
from limes.mcp.tools import inventory, issues  # noqa: F401
