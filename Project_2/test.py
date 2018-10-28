#!/bin/bash .

import subprocess
import random

POWER_OF_MAX_NUMBER_OF_OBJECTS = 17
POWER_OF_MAX_SIZE_OF_OBJECTS = 17
MAX_NUMBER_OF_TASKS = 9
MAX_NUMBER_OF_CONTAINERS = 9


class Tester:

    def __init__(self):
        self.total_tests = 0
        self.device_error = 0
        self.error_messages = []

    def run_test(self, objects, size, tasks, containers):
        command = ['./test.sh', str(objects), str(size), str(tasks), str(containers)]
        '''command = './test.sh {} {} {} {}'.format(2**num_of_objects, 2**size_of_objects, tasks, containers)'''
        subprocess.check_call(['bash', '-c', 'sudo dmesg --clear'])
        print(command)
        output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode('UTF-8')
        passes = output.count('Pass')
        if 'Device open failed' in output:
            self.device_error = device_error + 1
            self.error_messages.append(output)
            return
        elif passes != containers:
            print('Failed: {}'.format(output))
            exit(1)
        self.total_tests += 1
        print('{}\nTotal Tests Passed: {}\n'.format(output, self.total_tests))

    def test_variations(self):
        for num_of_objects in range(POWER_OF_MAX_NUMBER_OF_OBJECTS):
            for size_of_objects in range(1, POWER_OF_MAX_SIZE_OF_OBJECTS):
                for tasks in range(1, MAX_NUMBER_OF_TASKS):
                    for containers in range(1, MAX_NUMBER_OF_CONTAINERS):
                        self.run_test(2**num_of_objects, 2**size_of_objects, 2**tasks, 2**containers)
        print('Success!!!')

    def test_loop(self, objects, size, tasks, containers, iterations=100):
        for i in range(iterations):
            self.run_test(objects, size, tasks, containers)
        print('Success!!!')


if __name__ == '__main__':
    tester = Tester()
    #tester.test_variation()
    tester.test_loop(128, 8, 64, 64)

    if tester.device_error:
        print('\nDevice open failed Error occurred {} times with the following errors:\n{}'.format(tester.device_error, '\n'.join(tester.error_messages)))
