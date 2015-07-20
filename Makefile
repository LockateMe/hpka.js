all: out/sodium.js out/hpka.js
	cp -r out/* test/
	cp hpka.js out/
	cp hpka.js test/

out/sodium.js: libsodium-js/out/sodium.js
	mkdir -p out/
	cd libsodium-js && cp -r out/* ../out
	cp hpka.js out/hpka.js

libsodium-js/out/sodium.js: libsodium-js/Makefile
	cd libsodium-js && make

libsodium-js/Makefile:
	git submodule update --init --recursive

test: out/sodium.js test/server_built
	cp out/* test/
	echo "Go to http://localhost:2500/test.html to test hpka.js"
	iojs test/server.js || nodejs test/server.js || node test/server.js

test/server_built:
	cd test && npm install
	touch test/server_built

rewrap: libsodium-js/out/sodium.js
	cd libsodium-js && make rewrap
	cp libsodium-js/out/* out/
	cp out/* test

clean:
	-rm -r out
	cd libsodium-js && make distclean

clean-test:
	-rm -rf test/node_modules
	-rm test/server_built
	-rm test/libsodium.js
	-rm test/sodium.js
	-rm test/hpka.js
