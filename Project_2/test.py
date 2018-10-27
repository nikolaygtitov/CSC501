#!/bin/bash .

import subprocess
import random

POWER_OF_MAX_NUMBER_OF_OBJECTS = 17
POWER_OF_MAX_SIZE_OF_OBJECTS = 17
MAX_NUMBER_OF_TASKS = 101
MAX_NUMBER_OF_CONTAINERS = 101

total_tests = 0
device_error = 0

for num_of_objects in range(POWER_OF_MAX_NUMBER_OF_OBJECTS):
    for size_of_objects in range(1, POWER_OF_MAX_SIZE_OF_OBJECTS):
        for tasks in range(1, MAX_NUMBER_OF_TASKS):
            for containers in range(1, MAX_NUMBER_OF_CONTAINERS):
                command = ['./test.sh', str(2**num_of_objects), str(2**size_of_objects), str(tasks), str(containers)]
                '''command = './test.sh {} {} {} {}'.format(2**num_of_objects, 2**size_of_objects, tasks, containers)'''
                subprocess.check_call(['bash', '-c', 'sudo dmesg --clear'])
                print(command)
                output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode('UTF-8')
                passes = output.count('Pass')
                if output == 'Device open failedcat: \'*.log\': No such file or directory\nDevice open failed':
                    device_error = device_error + 1
                    continue
                elif passes != containers:
                    print('Failed: {}'.format(output))
                    exit(1)
                total_tests = total_tests + 1
                print('{}\nTotal Tests Passed: {}\n'.format(output, total_tests))
print('Success!!!')

if device_error:
    print('\nDevice open failed Error occurred {} times.'.format(device_error))
