rm -rf bin
mkdir bin

../../Odin/odin build . -out:./debug -debug -o:minimal
../../Odin/odin build ./tests/multiple_files -out:./bin/multiple_files -debug
../../Odin/odin build ./tests/single_file -out:./bin/single_file -debug
clang -O0 -g -o ./bin/simple_c ./tests/simple_c/main.c
clang -O0 -g -o ./bin/multifunc_c ./tests/multifunc_c/main.c
