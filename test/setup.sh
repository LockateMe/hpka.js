#! /bin/sh

if [ -d "./node_modules" ]
then
	echo "Server packages already installed\n"
else
	echo "Installing the server's packages\n"
	npm install
fi
if [ -d "./libsodium" ]
then
	echo "Libsodium is already cloned. Pulling latest commits\n"
	cd libsodium
	git pull origin master
	cd ..
else
	echo "Cloning libsodium\n"
	git clone https://github.com/LockateMe/libsodium.git
fi
cd libsodium
echo $(pwd)
./autogen.sh
./dist-build/emscripten.sh
cp libsodium-js/lib/libsodium.js* ../../
cp libsodium-js/lib/libsodium-wrap.js ../../
