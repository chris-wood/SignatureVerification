import sys
import os
import tempfile
import subprocess
import csv
import argparse
import random
from subprocess import Popen, PIPE

def main(args):
	times = []

	seed = args.randomseed

	payloadMinimum = 2 ** int(args.payloadsize)
	payloadMaximum = 2 ** (int(args.payloadsize) + 1)
	payload = random.randint(payloadMinimum, payloadMaximum)

	for n in args.trials:
		for size in args.sizes:
			# verifierOutputLines = subprocess.check_output(['./verifier', ], stdin=payload).splitlines()
			p = Popen(['./verifier', str(size), str(seed)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
			stdout, stderr = p.communicate(str(payload))
			for line in stdout:
				line = line.strip()
				if len(line) > 0:
					times.append(stdout)
	for timeLine in times:
		print timeLine

if __name__ == '__main__':
	desc = '''
Run the verifier. 

$> python verifier-runner.py -t 100 -s 128 256 -r RANDOMSEEDFORTHISTEST
YYY
'''

	parser = argparse.ArgumentParser(prog='verifier-runner', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
	parser.add_argument('-t', '--trials', required=True, help="Number of experiment trials.")
	parser.add_argument('-s', '--sizes', nargs='+', required=True, help="Key sizes to test.")
	parser.add_argument('-r', '--randomseed', required=True, help="Random seed.")
	parser.add_argument('-p', '--payloadsize', required=True, help="Payload size for all signatures.")

	args = parser.parse_args()

	main(args)