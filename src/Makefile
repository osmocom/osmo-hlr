LDFLAGS += -losmocore -losmogsm -losmoabis -lsqlite3 -ltalloc
CFLAGS += -g -Wall

OBJS = auc.o db.o db_auc.o db_hlr.o logging.o

all: db_test hlr

db_test: db_test.o rand_fake.o $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

hlr: hlr.o gsup_server.o gsup_router.o rand_urandom.o $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f *.o db_test
