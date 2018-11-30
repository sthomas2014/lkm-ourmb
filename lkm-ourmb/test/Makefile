##
## Makefile for lkm-ourmb
##
## Made by xsyann
## Contact <contact@xsyann.com>
##
## Modified by Scott Thomas, Jiacheng Liu, Quinn Wu
##
##

TARGET	= test
SRC	= test.c
OBJ	= $(SRC:.c=.o)
CC	= gcc -std=c11 -pedantic
CFLAGS	+= -W -Wall
RM	= rm -vf


$(TARGET): $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

all	: $(TARGET)

clean	:
	$(RM) $(OBJ) *~ \#*#

fclean	: clean
	$(RM) $(TARGET)

re	: fclean all clean

.PHONY	: clean fclean re
