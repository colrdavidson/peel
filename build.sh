rm -rf bin
mkdir bin

../Odin/odin build debug.odin -opt:2 -out:./debug -debug
../Odin/odin build ./tests/multiple_files -out:./bin/multiple_files -debug
../Odin/odin build ./tests/single_file -out:./bin/single_file -debug
clang -g -o ./bin/simple_c ./tests/simple_c/main.c
