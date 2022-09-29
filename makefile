
execas:
	# install the binary into the bin folder
	cargo install --path . --root .

	# set the file owner to root (and group)
	chown root ./bin/execas

	# set the setuid bit
	chmod u+s ./bin/execas
