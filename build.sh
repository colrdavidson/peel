rm -rf bin
mkdir bin

../Odin/odin build debug.odin -out:./bin/debug -debug
../Odin/odin build ./tests/multiple_files -out:./bin/multiple_files -debug
../Odin/odin build ./tests/single_file -out:./bin/single_file -debug
