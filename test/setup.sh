#! /bin/sh

if [ -d "./node_modules" ]
then
	echo "Server packages already installed"
else
	echo "Installing the server's packages"
	npm install
fi
if [ -d "./libsodium" ]
then
	echo "Libsodium is already cloned. Pulling latest commits"
	cd libsodium
	git pull origin master
else
	echo "Cloning libsodium"
	git clone https://github.com/LockateMe/libsodium.git
	cd libsodium
fi
./autogen.sh
./dist-build/emscripten.sh
cp libsodium-js/lib/libsodium.js* ../
cp libsodium-js/lib/libsodium-wrap.js ../
cp ../hpka.js ./
