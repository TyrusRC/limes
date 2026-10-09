from startScan.models import Command


class DbCommandRecorder:
    """Persist a command's output tail; at most one UPDATE per flush interval."""

    def __init__(self, command_obj):
        self.pk = command_obj.pk

    def update(self, output_tail):
        Command.objects.filter(pk=self.pk).update(output=output_tail)

    def finish(self, result):
        Command.objects.filter(pk=self.pk).update(output=result.output_tail, return_code=result.return_code)
