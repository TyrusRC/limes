import ast
import pathlib

from django.test import SimpleTestCase

WEB = pathlib.Path(__file__).resolve().parents[2]


class NoJoinInsideTasksTest(SimpleTestCase):
    def test_no_allow_join_result(self):
        offenders = [str(p) for p in list((WEB / 'limes').glob('*.py')) + list((WEB / 'limes' / 'tasks').glob('*.py')) + list((WEB / 'api').glob('*.py'))
                     if 'allow_join_result' in p.read_text()]
        self.assertEqual(offenders, [])


def _is_app_task(fn):
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute) and target.attr == 'task':
            return True
    return False


def _blocks_on_children(fn):
    for node in ast.walk(fn):
        if isinstance(node, ast.While):
            t = node.test
            if (isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not)
                    and isinstance(t.operand, ast.Call)
                    and getattr(t.operand.func, 'attr', None) == 'ready'):
                return True
        if (isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == 'get'
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ('job', 'result', 'results', 'task', 'group_result')):
            return True
    return False


def blocking_tasks():
    trees = [ast.parse(p.read_text()) for p in (WEB / 'limes' / 'tasks').glob('*.py')]
    return sorted(f.name for tree in trees for f in ast.walk(tree)
                  if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and _is_app_task(f) and _blocks_on_children(f))


class BlockingCoordinatorsTest(SimpleTestCase):
    def test_no_task_blocks_on_children(self):
        # Phase 0B deleted every blocking poll-loop coordinator. No @app.task in
        # limes/tasks/ may wait on its children (while not <x>.ready() / <job>.get()),
        # which permanently closes the 0A orchestrate-pool deadlock.
        self.assertEqual(blocking_tasks(), [])
