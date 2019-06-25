import time

with open("test.write", 'w') as fhandle:
	while True:
		fhandle.write("1" * 100)
		time.sleep(1)
