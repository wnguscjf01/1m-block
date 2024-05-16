all: 1m-block

1m-block:
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	g++ -o 1m-block main.cpp -lnetfilter_queue
clean:
	sudo iptables -F
	rm -f 1m-block
	rm -f index*
	rm -f output*