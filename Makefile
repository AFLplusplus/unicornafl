.PHONY: all debug debug release run test

all: build/libunicornafl

build:
	mkdir build

unicorn/build/libunicorn-common.a:
	git submodule update --init --recursive
	cmake -S unicorn/ -B unicorn/build -D BUILD_SHARED_LIBS=no
	$(MAKE) -C ./unicorn/build -j8

build/libunicornafl: build unicorn/build/libunicorn-common.a
	cd ./build && cmake .. -D BUILD_SHARED_LIBS=no
	$(MAKE) -C ./build -j8

format:
	format.sh

clean:
	rm -rf build
	rm -rf ./unicorn/build
