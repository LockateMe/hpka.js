all: out/sodium.js out/hpka.js
	cp -r out/* test/
	cp hpka.js out/
	cp hpka.js test/

compile:
	cd libsodium-js && make distclean && make
	-rm -r out/
	make all

out/sodium.js: libsodium-js/Makefile
	cd libsodium-js && node test/test.js && cd ..
	mkdir -p out/
	cd libsodium-js && cp -r dist/browsers/combined/* ../out
	cp hpka.js out/hpka.js

#libsodium-js/out/sodium.js: libsodium-js/Makefile
#	cd libsodium-js && node test/test.js

libsodium-js/Makefile:
	git submodule update --init --recursive

test: out/sodium.js test/server_built
	cp out/* test/
	# echo "Go to http://localhost:2500/test.html to test hpka.js"
	iojs test/index.js || nodejs test/index.js || node test/index.js

test/server_built:
	npm install
	touch test/server_built

rewrap: libsodium-js/out/sodium.js
	cd libsodium-js && make rewrap
	cp libsodium-js/out/* out/
	cp out/* test

clean:
	-rm -r out
#	cd libsodium-js && make distclean

clean-test:
	-rm -rf test/node_modules
	-rm test/server_built
	-rm test/libsodium.js
	-rm test/sodium.js
	-rm test/hpka.js
