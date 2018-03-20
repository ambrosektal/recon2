import threading
import time
from queue import Queue

from resources import threaded

q = Queue()
print_lock = threading.Lock()


def example_job(worker):
    time.sleep(0.5)
    with print_lock:
        print(threading.current_thread().name, worker) #prevents the print from printing until unlocked

@threaded
def threader(): #Actually performing the threading operation
     while True:
         worker = q.get() # getting the worker from the queue and putting the worker t work.
         example_job(worker)
         q.task_done()

for x in range(10): # number of threads / workers
    threader()
#     #t = threading.Thread(target=threader)
#     t = threading.Thread(target=threader)
#     t.daemon = True #will die when the main thread dies
#     t.start()

start = time.time()

for worker in range(20): #20 instances of workers / how many total jobs to run.
    q.put(worker) #putting worker to work

q.join() #waits till thread terminates

print("Entire job took: ",time.time()-start)





