import eventlet
from eventlet.green import socket
import random
import time




try:
    c = socket.socket()
    c.connect(('10.108.207.99',6000))
    print("connected")
    while True:
        number = str(random.randrange(5,30))
        data = c.sendall(number)
        time.sleep(5)
except (SystemExit,KeyboardInterrupt):
        exit()

finally:
    c.close()

