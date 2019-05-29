CC=emcc
OUTPUT_FOLDER=./build

build:
	mkdir $(OUTPUT_FOLDER)
	$(CC) ./src/main.c -O3 -s WASM=1 -o $(OUTPUT_FOLDER)/index.html --shell-file ./src/challenge_shell.html -s NO_EXIT_RUNTIME=1 -s LINKABLE=1 -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall"]'
	wasm2wat $(OUTPUT_FOLDER)/index.wasm -o $(OUTPUT_FOLDER)/index.wat
	truncate -s -2 $(OUTPUT_FOLDER)/index.wat
	echo "\n(start 33))" >> $(OUTPUT_FOLDER)/index.wat
	wat2wasm $(OUTPUT_FOLDER)/index.wat -o $(OUTPUT_FOLDER)/index.wasm

clean:
	rm -rf $(OUTPUT_FOLDER)/

