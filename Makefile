all:
	gcc vpn_server.c -o vpn_server -lssl -lcrypto
	gcc vpn_client.c -o vpn_client -lssl -lcrypto
clean:
	rm vpn_server vpn_client
