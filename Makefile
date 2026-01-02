CC=cc
DAE=paradosd

all: parados

parados:
	$(CC) server/*.c -o $(DAE)
