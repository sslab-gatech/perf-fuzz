CFLAGS := -O0
LDFLAGS := 
ALL := target

all: $(ALL)

target: target.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(ALL)