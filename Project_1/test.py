#!/bin/bash .

import subprocess
import random

NUMBER_OF_CONTAINERS = '100'

def get_command(containers):
    command = ['./test.sh', str(containers)]
    for container in range(0, containers):
        command.append(str(random.randint(1, 101)))
    return command

for containers in range(1, 10):
    subprocess.check_call(['bash', '-c', 'sudo dmesg --clear'])
    subprocess.check_call(get_command(containers))
    subprocess.check_call(['bash', '-c', 'dmesg | grep csc'])

print('DONE')
