
import subprocess
import re


class TestParser:
    NUM_OF_CONTAINERS_RE = re.compile("num_of_containers:\s+(?P<num>\d+)")
    NUM_OF_TASKS_RE = re.compile("num_of_total_tasks:\s+(?P<num>\d+)")
    TASK_RE = re.compile("task\sfor\scontainer\s(?P<cid>\d+):\s+(?P<num>\d+)")
    TID_RE = re.compile("TID:\s+(?P<tid>\d+),\s+Container:\s+(?P<cid>\d+),\s+Processed:\s+(?P<processed>\d+)")

    def __init__(self, output):
        self.output = output

    @property
    def number_of_containers(self):
        match = self.NUM_OF_CONTAINERS_RE.search(self.output)
        if match:
            return int(match.groupdict()['num'])
        raise Exception('Cannot find number of containers')

    @property
    def number_of_tasks(self):
        match = self.NUM_OF_TASKS_RE.search(self.output)
        if match:
            return int(match.groupdict()['num'])
        raise Exception('Cannot find number of tasks')

    @property
    def number_of_tasks_for_container_dict(self):
        matches = self.NUM_OF_TASKS_RE.findall(self.output)
        return {int(md['cid']): int(md['num']) for md in [m.groupdict() for m in matches]}

    def get_number_of_tasks_for_container(self, cid):
        if cid in self.number_of_tasks_for_container_dict:
            return self.number_of_tasks_for_container_dict[cid]
        raise Exception('Cannot find number of tasks in container ' + str(cid))

    @property
    def total_processed(self):
        matches = self.TID_RE.findall(self.output)
        return sum([int(md['processed']) for md in [m.groupdict() for m in matches]])

    def get_total_processed_for_container(self, cid):
        matches = self.TID_RE.findall(self.output)
        


if __name__ == '__main__':
    i = 0
    stop = False
    while not stop:
        print 'Run ' + str(i)
        test_output = subprocess.check_output(['./test.sh', '2', '2', '1'], stderr=subprocess.STDOUT, universal_newlines=True)
        print test_output

        parser = TestParser(test_output)

        num_containers = parser.number_of_containers
        num_tasks = parser.number_of_tasks

        i += 1
