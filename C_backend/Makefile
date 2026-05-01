# Փոփոխականներ
CC = gcc
CFLAGS = -O2 -Wall -Wextra
LIBS = -lcrypto
DEST = /home/vahe/Desktop/MyProj/C_Backend

# Հիմնական թիրախը (երբ գրում ես ուղղակի 'make')
all: provisioner dev1_bin dev2_bin sender receiver

# 1. Provisioner կոմպիլյացիա
provisioner: provisioner.c
	$(CC) $(CFLAGS) provisioner.c -o provisioner $(LIBS)

# 2. Node D1 (ROLE=1)
dev1_bin: secure_bridge.c
	$(CC) $(CFLAGS) -DROLE=1 secure_bridge.c -o dev1_bin $(LIBS)

# 3. Node D2 (ROLE=2)
dev2_bin: secure_bridge.c
	$(CC) $(CFLAGS) -DROLE=2 secure_bridge.c -o dev2_bin $(LIBS)

# 4. File Sender
sender: sender.c
	$(CC) $(CFLAGS) sender.c -o sender

# 5. File Receiver
receiver: receiver.c
	$(CC) $(CFLAGS) receiver.c -o receiver

# Մաքրել բոլոր բինար ֆայլերը և բանալիները
clean:
	rm -f dev1_bin dev2_bin provisioner sender receiver
	rm -rf dev1_keys dev2_keys