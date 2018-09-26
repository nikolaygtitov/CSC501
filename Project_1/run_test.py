
import sys
import subprocess
import re
import random
import math


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
        matches = self.TASK_RE.findall(self.output)
        return {int(m[0]): int(m[1]) for m in matches}

    def get_number_of_tasks_for_container(self, cid):
        if cid in self.number_of_tasks_for_container_dict:
            return self.number_of_tasks_for_container_dict[cid]
        raise Exception('Cannot find number of tasks in container ' + str(cid))

    def iter_tasks_in_container(self, cid):
        matches = self.TID_RE.findall(self.output)
        for m in matches:
            if int(m[1]) == cid:
                yield int(m[0])

    @property
    def total_processed(self):
        matches = self.TID_RE.findall(self.output)
        return sum([int(m[2]) for m in matches])

    def get_total_processed_for_container(self, cid):
        matches = self.TID_RE.findall(self.output)
        return sum([int(m[2]) for m in matches if int(m[1]) == cid])

    def get_processed_for_task(self, tid):
        matches = self.TID_RE.findall(self.output)
        for match in matches:
            if int(match[0]) == tid:
                return int(match[2])
        return 0

    @property
    def containers(self):
        containers = self.number_of_tasks_for_container_dict.keys()
        containers.sort()
        return containers


def print_color(color, str):
    if color == 'red':
        str = u'\u001b[31m' + str
    elif color == 'green':
        str = u'\u001b[32m' + str
    print str + u'\u001b[0m'


def clear_dmesg():
    subprocess.check_call(['bash', '-c', 'sudo dmesg --clear'])


if __name__ == '__main__':
    i = 0
    stop = False

    c = sys.argv[1]
    t = sys.argv[2:]
    if len(t) < int(c):
        t = t + [t[-1]] * (int(c) - len(t))

    while not stop:
        print '\nRun ' + str(i)

        clear_dmesg()

        test_output = subprocess.check_output(['./test.sh', c] + t, stderr=subprocess.STDOUT, universal_newlines=True)
        print test_output

        parser = TestParser(test_output)

        num_containers = parser.number_of_containers
        num_tasks = parser.number_of_tasks
        total_processed = parser.total_processed
        containers = parser.containers

        # Check percent processed for each container
        exp_processed_c = total_processed / float(len(containers))
        for cid in containers:
            act_processed_c = parser.get_total_processed_for_container(cid)
            pct_error_processed_c = abs((act_processed_c - exp_processed_c) / exp_processed_c) * 100
            if pct_error_processed_c < 10:
                col = 'green'
            else:
                col = 'red'
                stop = True
            print_color(col, 'Container %d: %d/%d => %d%%' % (cid, act_processed_c, exp_processed_c, pct_error_processed_c))

            # Check percent processed for each task in container
            exp_processed_t = exp_processed_c / float(parser.get_number_of_tasks_for_container(cid))
            for tid in parser.iter_tasks_in_container(cid):
                act_processed_t = parser.get_processed_for_task(tid)
                pct_error_processed_t = abs((act_processed_t - exp_processed_t) / exp_processed_t) * 100
                if pct_error_processed_t < 10:
                    col = 'green'
                else:
                    col = 'red'
                    stop = True
                print_color(col, '    Task %d: %d/%d => %d%%' % (tid, act_processed_t, exp_processed_t, pct_error_processed_t))

        i += 1
