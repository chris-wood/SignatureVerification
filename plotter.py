"""
Demo of the errorbar function, including upper and lower limits
"""
import numpy as np
import matplotlib.pyplot as plt

lines = []
domainValues = []
algs = {}
minTime = 2**20 # ridiculous
maxTime = 0
with open("verify.csv") as datafile:
	for line in datafile:
		lineParts = line.strip().split(",")
		domain = int(lineParts[3])
		if not domain in domainValues:
			domainValues.append(domain)
		algName = lineParts[0]
		keySize = lineParts[1]
		keyName = algName + "-" + keySize
		if not keyName in algs:
			algs[keyName] = []
		time = int(lineParts[5])
		payload = int(lineParts[3])
		algs[keyName].append((payload, time))

		if time < minTime:
			minTime = time
		if time > maxTime:
			maxTime = time

domainValues.sort()

# example data
# x = np.arange(start = domainValues[0], stop = domainValues[-1])
# y = np.arange(start = minTime, stop = maxTime)
# xerr = 0.1
# yerr = 0.2

ls = 'dotted'

fig = plt.figure()
ax = fig.add_subplot(1, 1, 1)
# plt.rc('axes', color_cycle=['r', 'g', 'b', 'y'])

color=iter(plt.cm.rainbow(np.linspace(0,1,len(algs))))

for keyName in algs:
	pairs = algs[keyName]
	stddev = np.std(pairs)
	c = next(color)

	domainTotals = {}
	for p in pairs:
		if not p[0] in domainTotals:
			domainTotals[p[0]] = []
		domainTotals[p[0]].append(p[1])

	x = []
	y = []
	for domain in domainValues:
		x.append(domain)
		y.append(reduce(lambda x, y: x + y, domainTotals[domain]) / len(domainTotals[domain]))


	# plt.errorbar([p[0] for p in pairs], [p[1] for p in pairs], yerr = stddev, color=c, ls=ls, label=keyName)
	plt.errorbar(x, y, color=c, label=keyName)

ax.set_color_cycle(['c', 'm', 'y', 'k'])

handles, labels = ax.get_legend_handles_labels()
ax.legend(handles, labels)

# standard error bars
# plt.errorbar(x, y, xerr=xerr, yerr=yerr, ls=ls, color='blue')

# including upper limits
# uplims = np.zeros(x.shape)
# uplims[[1, 5, 9]] = True
# plt.errorbar(x, y+0.5, xerr=xerr, yerr=yerr, uplims=uplims, ls=ls,
#              color='green')

# including lower limits
# lolims = np.zeros(x.shape)
# lolims[[2, 4, 8]] = True
# plt.errorbar(x, y+1.0, xerr=xerr, yerr=yerr, lolims=lolims, ls=ls,
#              color='red')

# # including upper and lower limits
# plt.errorbar(x, y+1.5, marker='o', ms=8, xerr=xerr, yerr=yerr,
#              lolims=lolims, uplims=uplims, ls=ls, color='magenta')

# # including xlower and xupper limits
# xerr = 0.2
# yerr = np.zeros(x.shape) + 0.2
# yerr[[3, 6]] = 0.3
# xlolims = lolims
# xuplims = uplims
# lolims = np.zeros(x.shape)
# uplims = np.zeros(x.shape)
# lolims[[6]] = True
# uplims[[3]] = True
# plt.errorbar(x, y+2.1, marker='o', ms=8, xerr=xerr, yerr=yerr,
#              xlolims=xlolims, xuplims=xuplims, uplims=uplims, lolims=lolims,
#              ls='none', mec='blue', capsize=0, color='cyan')

# ax.set_xlim((0, 5.5))
ax.set_title('Signature Verification Times')
plt.show()