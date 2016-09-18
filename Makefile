.SUFFIXES: .o .cpp

CC      = g++
CFLAGS  = -g -Wall -O2
LDFLAGS = -L/lib/x86_64-linux-gnu -lnl-3 -lnl-genl-3 -lnl-route-3 -lpthread -ljson-c
INCLUDE = -I/usr/include/libnl3 -I./include
LIBS    = 
SRC_DIR = ./src
OBJ_DIR = ./build
BIN_DIR = ./bin
SOURCES = $(shell ls $(SRC_DIR)/*.cpp) 
OBJS    = $(subst $(SRC_DIR),$(OBJ_DIR), $(SOURCES:.cpp=.o))
TARGETS = asteroid
DEPENDS = $(OBJS:.o=.d)

all: $(TARGETS)

$(TARGETS): $(OBJS) $(LIBS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $(OBJS) $(LDFLAGS)


$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp 
	@if [ ! -d $(OBJ_DIR) ]; \
		then echo "mkdir -p $(OBJ_DIR)"; mkdir -p $(OBJ_DIR); \
	fi
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ -c $<


clean:
	$(RM) $(OBJS) $(BIN_DIR)/$(TARGETS) $(DEPENDS)

-include $(DEPENDS)

.PHONY: clean
