pcap_test: main.c
	gcc -o pcap_test main.c -lpcap
clean:
	rm -rf pcap_test
