# Network_Security_2022
 Repository del corso di Network Security, corso del percorso formativo in Cybersecurity del CdL Magistrale in Ingegneria Informatica presso l'Università degli Studi di Napoli Federico II, tenuto dal professore Romano
# Modified libssh and client

1) git clone https://github.com/libssh/libssh-mirror.git
2) replace the kex.c file in /libssh-mirror/src with the one in the folder client
2) cd libssh-mirror && mkdir build && cd build
3) cmake ../ -DWITH_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_STATIC_LIB=ON
4) make
compile client.c linking the static libssh.a file:
5) gcc -I/.../libssh-mirror/include -I/.../libssh-mirror/build/include client.c /.../libssh-mirror/build/src/libssh.a -lssh -lrt -lcrypto -lz -lpthread -ldl -o client

# Wireshark dissector, tested for wireshark 3.6.x

1) sudo apt-get install liblua5.2-dev
2) sudo apt-get install libssl-dev
3) git clone --recurse https://github.com/zhaozg/lua-openssl.git lua-openssl  :  great lib used to bind the plugin to openssl for the decryption
4) cd lua-openssl
5) make LUA_CFLAGS=-I/usr/include/lua5.2
6) mv the openssl.so in the folder usr/lib/lua/5.2 dir (if doesn't exist create it)
7) move the ssh_postdissector.lua and the ssh_postdissector folder to the custom lua plugin folder of wireshark (you can find it in wireshark->help->informations->folders->personal lua plugins)
8) reload lua plugins (analyze->reload lua plugins)
9) you can enable the dissector and configure the session keys in the preference tab (SSH_Payload protocol)