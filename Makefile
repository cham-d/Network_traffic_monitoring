all: monitor

monitor: monitor.c
	gcc -g monitor.c listLib.c -o monitor -lpcap 

clean:
	rm -rf monitor
