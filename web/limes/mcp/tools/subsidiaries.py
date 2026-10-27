"""Read tools: subsidiary scores and saved portfolios. Names are user text, so they go out through untrusted()."""
from limes import portfolios, subsidiaries
from limes.mcp import access
from limes.mcp.registry import tool
from limes.mcp.results import Slug, untrusted


@tool(title='List subsidiaries')
def list_subsidiaries(caller, project: Slug):
    """The project's subsidiaries, each with its own score, grade, open issues and asset count, scored like the project score over its assets only. The project score does not include or change with them."""
    p = access.project_for(caller, project)
    return {'items': [{**{k: v for k, v in r.items() if k != 'name'}, 'name': untrusted(r['name'])}
                      for r in subsidiaries.scores(p)]}


@tool(title='List portfolios')
def list_portfolios(caller, project: Slug):
    """The project's saved portfolios: named filters over tags and/or a subsidiary, plus hand-picked assets."""
    p = access.project_for(caller, project)
    return {'items': [{**r, 'name': untrusted(r['name']), 'subsidiary': untrusted(r['subsidiary']) if r['subsidiary'] else None}
                      for r in portfolios.listing(p)]}
