"""Tool registry and the one call path. Every tool is registered here and runs only through call_tool."""
import dataclasses
import importlib
import inspect
import logging
import time
from dataclasses import dataclass
from typing import Callable
from pydantic import ValidationError, validate_call
from dashboard.models import ApiToken
from limes.mcp import access, audit, results, tokens
from limes.mcp.access import McpError

logger = logging.getLogger(__name__)


@dataclass
class ToolSpec:
    name: str
    fn: Callable  # validated wrapper: what call_tool runs
    write: bool
    perm: str | None
    destructive: bool
    title: str
    description: str
    open_world: bool = False
    raw: Callable = None  # the undecorated function, for signature inspection (FastMCP schema, scoping sweeps)


REGISTRY: dict[str, ToolSpec] = {}


def tool(*, title, write=False, perm=None, destructive=False, open_world=False):
    # NOTE: tool() returns the bare function and ToolSpec.raw exposes it for signature inspection (Task 5 sweep).
    # The transport must call tools only through call_tool, never raw: raw skips authorization.
    def deco(fn):
        if fn.__name__ in REGISTRY:
            raise ValueError(f'duplicate MCP tool {fn.__name__}')
        if write and not perm:
            raise ValueError(f'write tool {fn.__name__} needs a permission')
        if any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in inspect.signature(fn).parameters.values()):
            raise ValueError(f'tool {fn.__name__} must not take *args or **kwargs')
        REGISTRY[fn.__name__] = ToolSpec(
            fn.__name__, validate_call(config={'arbitrary_types_allowed': True})(fn), write, perm, destructive, title,
            (fn.__doc__ or '').strip(), open_world, fn)
        return fn
    return deco


def annotations(spec):
    return {'title': spec.title, 'readOnlyHint': not spec.write,
            'destructiveHint': spec.destructive if spec.write else None, 'openWorldHint': spec.open_world}


def load_tools():
    importlib.import_module('limes.mcp.tools')
    return REGISTRY


def _invalid(e):
    # loc: msg only. Never the input values: they are the agent's text and may hold a secret.
    parts = [f"{'.'.join(results.clean(str(p), 60) for p in err['loc'])}: {results.clean(err['msg'], 120)}"
             for err in e.errors()[:5]]
    return McpError('invalid', 'invalid arguments: ' + '; '.join(parts))


def _has_nul(v):
    if isinstance(v, str):
        return '\x00' in v
    if isinstance(v, dict):
        return any(_has_nul(k) or _has_nul(x) for k, x in v.items())
    if isinstance(v, (list, tuple)):
        return any(_has_nul(x) for x in v)
    return False


def _run(name, token_pk, args, now, state):
    state['caller'] = caller = access.resolve_caller(token_pk, now)
    spec = REGISTRY.get(name)  # only after authentication: a stranger learns nothing about tool names
    access.check_rate(caller, bool(spec and spec.write))
    if spec is None:
        raise McpError('invalid', 'unknown tool')
    if spec.write:
        access.require_write(caller, spec.perm)
        state['caller'] = caller = dataclasses.replace(caller, write=True)
    elif spec.perm:
        access.require(caller, spec.perm)
    if 'caller' in args:
        raise McpError('invalid', 'invalid arguments: caller: reserved name')
    if _has_nul(args):  # Postgres cannot store NUL; refuse it up front instead of failing deep in a tool
        raise McpError('invalid', 'invalid arguments: NUL characters are not allowed')
    try:
        data = spec.fn(caller, **args)
    except ValidationError as e:
        raise _invalid(e) from None
    return results.ok(data)


def call_tool(name, token_pk, args, now=None):
    """Never raises. resolve -> rate limit -> permission -> run -> envelope; audit and touch in finally."""
    started, state, outcome = time.monotonic(), {}, 'internal'
    spec = REGISTRY.get(name)
    args = args if isinstance(args, dict) else {}
    try:
        env = _run(name, token_pk, args, now, state)
        outcome = 'ok'
        return env
    except McpError as e:
        outcome = e.code
        return e.envelope()
    except Exception:  # the exception text may hold internals or secrets: it stays in the server log
        logger.exception('MCP tool %s failed', name)
        return McpError('internal', 'internal error; see the server log').envelope()
    finally:
        _finish(name, spec, token_pk, args, state.get('caller'), outcome, started)


def _finish(name, spec, token_pk, args, caller, outcome, started):
    try:
        tok_id, user_id, pk = '', None, None
        if token_pk is None:
            return  # nothing to attribute: no audit row for an unauthenticated caller
        if caller:
            tok_id, user_id, pk = caller.token.token_id, caller.user.id, caller.token.pk
        elif token_pk is not None:
            row = ApiToken.objects.filter(pk=token_pk).values_list('token_id', 'user_id').first()
            if row:
                (tok_id, user_id), pk = row, token_pk
        if pk is None:
            return
        project = args.get('project')
        audit.log_call(token_pk=pk, token_public_id=tok_id, user_id=user_id, tool=name,
                       project=project if isinstance(project, str) else '', args=args, outcome=outcome,
                       write=bool(spec and spec.write), duration_ms=int((time.monotonic() - started) * 1000))
        if caller:
            tokens.touch(caller.token)
    except Exception:
        logger.exception('MCP post-call bookkeeping failed (tool=%s)', name)
