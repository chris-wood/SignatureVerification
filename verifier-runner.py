import sys
import os
import tempfile
import subprocess
import csv
import argparse
import random
from subprocess import Popen, PIPE

def main(args):
	signTimes = []
	verifyTimes = []

	seed = args.randomseed

	for payloadSize in args.payloadsizes:
		payload = os.urandom(int(payloadSize))

		for size in args.keysizes:
			for n in range(int(args.trials)):
				print >> sys.stderr, len(str(payload)), str(size), str(n)
				p = Popen(['./verifier', str(size), str(seed)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
				stdout, stderr = p.communicate(str(payload))
				for line in stdout.split("\n"):
					line = line.strip()
					if len(line) > 0:
						if ("sign" in line):
							signTimes.append(line)
						else: 
							verifyTimes.append(line)
	if args.sign:
		for signTime in signTimes:
			print signTime
	if args.verify:
		for verifyTime in verifyTimes:
			print verifyTime

if __name__ == '__main__':
	desc = '''
Run the verifier. 

Example: 
python verifier-runner.py -t 100 -k 112 -r RANDOMSEEDFORTHISTESTTESTTESTEASDASDAS -p 128 256 512 1024 2048 4096 8192 16384 32768 65536 -v
<list of CSV lines>
'''

	parser = argparse.ArgumentParser(prog='verifier-runner', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
	parser.add_argument('-t', '--trials', required=True, help="Number of experiment trials.")
	parser.add_argument('-k', '--keysizes', nargs='+', required=True, help="Key sizes to test.")
	parser.add_argument('-r', '--randomseed', required=True, help="Random seed.")
	parser.add_argument('-p', '--payloadsizes', nargs='+', required=True, help="Payload size for all signatures.")
	parser.add_argument('-s', '--sign', default=False, required=False, action="store_true", help="Output signature generation times.")
	parser.add_argument('-v', '--verify', default=False, required=False, action="store_true", help="Output verification times.")

	args = parser.parse_args()

	if not (args.sign or args.verify):
		parser.print_help()
	else:
		main(args)