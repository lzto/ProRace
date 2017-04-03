#!/usr/bin/python
import numpy as np
import matplotlib.pyplot as plt

from matplotlib.backends.backend_pdf import PdfPages

data = np.genfromtxt('recov.csv', delimiter=',')

fig=plt.figure()

plt.plot(data[:,1],'r.',label='total')
#plt.plot(data[:,0],'bo',label='skip')
plt.plot(data[:,1]-data[:,0],'g.',label='recovered')

recov_rate = 1 - np.sum(data[:,0])/np.sum(data[:,1])

plt.title('Recover rate: %.2f' % recov_rate)

plt.xlabel('branch')
plt.ylabel('instruction')
plt.legend()
plt.show()

fig.savefig('recov.png')



