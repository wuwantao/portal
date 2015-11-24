portal.o:portal.c
	$(CC) $(CFLAGS)  $(LDFLAGS) -I/root/sda3/openwrt/build_dir/target-mipsel_24kec+dsp_musl-1.1.10/libnet-1.2-rc3/include -o portal portal.c -lnet -lsqlite3 -lpcap
	$(CC) $(CFLAGS)  $(LDFLAGS) -o main main.c md5.c  -lsqlite3
	chmod u+s main
clean:
	rm *.o portal
