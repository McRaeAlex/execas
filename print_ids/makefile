
execas: src/execas.c
	cc -Wall -Wextra -lc -o execas src/execas.c

	# copy the file 
	cp execas rootexecas

	# set the file owner to root (and group)
	chown root ./rootexecas

	# set the setuid bit
	chmod u+s ./rootexecas

.PHONY: clean ls
clean:
	rm rootexecas execas

ls:
	ls -la execas rootexecas
