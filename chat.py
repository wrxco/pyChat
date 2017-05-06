import threading
import argparse
import getpass
import socket
import struct
import base64
import json
import time
import sys
import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto import Random


class ChatClient():
    def __init__(self, multicast_host='224.2.24.42', multicast_port=9999,
                 client_host='0.0.0.0', client_port=9876,
                 user='bob', key='$btc'):
        self.user = user
        self.multicast_host = multicast_host
        self.multicast_port = multicast_port
        self.client_host = client_host
        self.client_port = client_port
        self.reg_hash = ''
        self.reg_time = str(time.time())
        self.reghashtxt = '{}{}{}'.format(self.user, self.reg_time,
                                          socket.gethostname())
        self.reghash = sha256(self.reghashtxt.encode()).hexdigest()[:16]
        server.reghash = self.reghash

        # Encryption initializations
        self.key = sha256(key.encode()).hexdigest()[:32]  # 256-bit key
        self.BS = 32  # 256-bit block size
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[:-ord(s[len(s)-1:])]

        self._register()

    def _encrypt(self, raw):
        raw = self.pad(raw)
        iv = Random.new().read(16)   # 128-bit IV required by AES
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return(base64.b64encode(iv + cipher.encrypt(raw)))

    def _register(self, bye=False):
        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx_sock.settimeout(.5)
        ttl = struct.pack('b', 1)  # Set IPv4 Multicast TTL value
        tx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        register = dict()
        if bye:
            register['cmd'] = 'bye'
        else:
            register['cmd'] = 'reg'
        register['user'] = self.user
        register['host'] = self.client_host
        register['port'] = self.client_port
        register['time'] = self.reg_time
        register['hash'] = self.reghash

        self._send(json.dumps(register), tx_sock, self.multicast_host,
                   self.multicast_port, True)

    def periodic_reg(self):
        while True:
            self._register()
            time.sleep(15)

    def _send(self, msg, tx_sock, host, port, udp=None):
        """
        Accept a tcp or multicast socket, host, and port and send data to the
        host via the socket. Send expects to receive a hash of the message back
        from a tcp message recipient.
        """

        enc_hash = sha256(msg.encode()).hexdigest()
        enc_msg = self._encrypt(msg)

        if udp:
            tx_sock.sendto(enc_msg, (host, port))
            tx_sock.close()
        else:
            try:
                tx_sock.connect((host, port))
                tx_sock.send(enc_msg)
                try:
                    data = tx_sock.recv(130)
                    tx_sock.close()
                except socket.timeout:
                    print('timed out, no response', file=sys.stderr)
            except socket.error:
                print('Unable to connect to {}:{}'.format(host, port))
            else:
                response = data.decode('utf-8')
                if response == enc_hash:
                    return(True)
                else:
                    return(False)

    def send_message(self, registrants, user, msg):
        response = None
        json_msg = dict()
        json_msg['cmd'] = 'msg'
        json_msg['msg'] = msg
        json_msg['user'] = self.user
        json_msg['port'] = self.client_port

        # print("Registrants is: {}".format(registrants))
        # print("User is: {}".format(user))
        # print("msg is: {}".format(msg))

        if user in registrants:
            tx_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            response = self._send(json.dumps(json_msg), tx_sock,
                                  registrants[user]['host'],
                                  registrants[user]['port'])
        else:
            print("User {} is not in the list of registrants.\n{}#: ".format(user, current_command), end='')

        if response:
            print("{} -> {} : OK!".format(msg, user, current_command))
            return(True)
        else:
            print("{} -> {} : Failed!".format(msg, user, current_command))
            return(False)


class ChatServer():
    def __init__(self, multicast_host='224.2.24.42', multicast_port=9999,
                 server_host='0.0.0.0', server_port=9876,
                 user='bob', key='$btc', reghash=''):

        # Server initializations
        self.multicast_host = multicast_host
        self.multicast_port = multicast_port
        self.server_host = server_host
        self.server_port = server_port
        self.user = user
        self.reghash = reghash

        # Data store initializations
        self.registrants = {}

        # Encryption initializations
        self.key = sha256(key.encode()).hexdigest()[:32]  # 256-bit key
        self.BS = 32  # 256-bit block size
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[:-ord(s[len(s)-1:])]

    def _decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]  # IV is the first 16 bytes of encrypted message
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return(self.unpad(cipher.decrypt(enc[16:])))

    def _encrypt(self, raw):
        raw = self.pad(raw)
        iv = Random.new().read(16)   # 128-bit IV required by AES
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return(base64.b64encode(iv + cipher.encrypt(raw)))

    def _chat_listen(self, server_host, server_port):
        """
        Listen for messages or registration commands via TCP.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server.bind((server_host, server_port))
        except socket.error:
            print('Unable to bind TCP chat server: {}'.format(server_port))
            print('Pick another port to bind to.')
            os._exit()

        server.listen(20)  # Set a backlog of 20 connections

        while True:
            connection, address = server.accept()
            new_connection = threading.Thread(target=self._run_chat_thread,
                                              args=(connection, address))
            new_connection.start()

    def _reg_listen(self, multicast_host, multicast_port):
        """
        Listen for registrations. Pass to _decode to ID commands.
        """
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            rx_sock.bind(('', multicast_port))
        except socket.error:
            print('Unable to bind UDP registration server: {}'.format(multicast_port))
            print('Pick another port to bind to.')
            os._exit()

        group = socket.inet_aton(multicast_host)  # Convert string into packed binary
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)  # 4 byte unsigned long string
        rx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # Set IPv4, and add membership to multicast IP.
        # receive packets on the network whose destination is the group address (but not our own)

        while True:
            data, address = rx_sock.recvfrom(1024)
            self._decode(data, address)

    def _decode(self, enc_msg, address):
        """
        Decrypt and decode json commands from other nodes on the network.
        """
        try:  # Decryption test. Ignore message if we can't decrypt. Implies sender using wrong key
            raw_msg = self._decrypt(enc_msg).decode('utf-8')
        except ValueError:
            print("Unable to decrypt message from: {}\n{}#: ".format(address[0],
                                                                    current_command), end='')
            return(False)

        try:  # Another decryption/message length test
            json_msg = json.loads(raw_msg)
        except json.decoder.JSONDecodeError:
            print("Unable to decrypt message from: {}\n{}#: ".format(address[0],
                                                                    current_command), end='')
            return(False)

        if json_msg['cmd'] == 'reg':  # Add a registrant to the network user list
            self._add_registrant(json_msg, address)
            return()
        elif json_msg['cmd'] == 'bye':  # Node left the network, so delete it from list
            self._del_registrant(json_msg, address)
            return()
        elif json_msg['cmd'] == 'msg':  # Message received, so print it
            msg_hash = sha256(raw_msg.encode()).hexdigest()
            print('{}: {}\n{}#: '.format(json_msg['user'], json_msg['msg'], current_command), end='')
            if json_msg['user'] in self.registrants:
                return(msg_hash)
            else:
                self._force_rereg(json_msg, address)
                return(msg_hash)
            return()
        elif json_msg['cmd'] == 'regnow':  # Another node doesn't know who we are
            msg_hash = sha256(raw_msg.encode()).hexdigest()
            # return reg command to re-send registration immediately
            client._register()
            return(msg_hash)
        elif json_msg['cmd'] == 'userdupe':  # The same user exists on the net, so exit.
            print("Another user with the name {} already exists on the network.".format(json_msg['user']))
            # Probably not the cleanest way to exit but we need to force
            # the user to pick another user name
            os._exit(1)
        else:
            return(False, False)

    def _del_registrant(self, json_msg, address):
        if json_msg['user'] in self.registrants:
            if json_msg['hash'] == self.registrants[json_msg['user']]['hash']:
                del self.registrants[json_msg['user']]
                print('User {}:{} has left the net.\n{}#: '.format(json_msg['user'],
                                                                  json_msg['hash'],
                                                                  current_command), end='')

    def _add_registrant(self, json_msg, address):
        """
        Check for user name in registrants. If it doesn't exist add it,
        else return True so we can notify client it's already registered
        on the network.
        """
        # print(json_msg)
        if json_msg['user'] == self.user:  # Reg with the same user as us
            if json_msg['hash'] == self.reghash:  # Also our own retransmission
                pass
            else:  # If not our own retransmission...
                print("Someone is trying to use your username!\n{}#: ".format(current_command), end='')
                self._notify_dupe_user(json_msg, address)
        elif json_msg['user'] not in self.registrants:
            print('Received registration message from {}:{}\n{}#: '.format(json_msg['user'],
                                                                          json_msg['hash'],
                                                                          current_command), end='')
            self.registrants[json_msg['user']] = dict()
            self.registrants[json_msg['user']]['time'] = json_msg['time']
            if json_msg['host'] == '0.0.0.0':
                self.registrants[json_msg['user']]['host'] = address[0]
            else:
                self.registrants[json_msg['user']]['host'] = json_msg['host']
            self.registrants[json_msg['user']]['port'] = json_msg['port']
            self.registrants[json_msg['user']]['hash'] = json_msg['hash']
            return(False)
        # elif self.registrants[json_msg['user']]['host'] == json_msg['host']:
            # This is just a registration re-broadcast.
            # return(False)
        elif self.registrants[json_msg['user']]['hash'] == json_msg['hash']:  # User with same hash is in registrants{}
            # This is just a registration re-broadcast.
            return(False)
        else:
            # return user, host, and port
            print("Duplicate user detected!\n{}#: ".format(current_command), end='')
            self._notify_dupe_user(json_msg, address)

    def _notify_dupe_user(self, msg, address):
        """
        Invocation of this function means another node on the net is aware of a
        different node that is using the same username. Forces script to exit.
        """
        msg['cmd'] = 'userdupe'
        enc_msg = self._encrypt(json.dumps(msg))

        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print('{}:{}'.format(address[0], msg['port']))
        try:
            tx_sock.connect((address[0], msg['port']))
            tx_sock.send(enc_msg)
            tx_sock.close()
        except ConnectionError:
            print("Unable to notify {}:{} of duplicate user name.\n{}#: ".format(address[0],
                                                                                msg['port'],
                                                                                current_command), end='')

    def _force_rereg(self, msg, address):
        msg['cmd'] = 'regnow'
        enc_msg = self._encrypt(json.dumps(msg))

        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tx_sock.connect((address[0], msg['port']))
            tx_sock.send(enc_msg)
            tx_sock.close()
        except socket.error:
            pass

    def _run_chat_thread(self, connection, address):
        """
        Handles all of the functions for each incoming chat connection.
        Accepts messages from clients. Sends hashed acknowledgements.
        """
        enc_msg = connection.recv(2048)  # Make this larger to accept longer messages
        msg_hash = self._decode(enc_msg, address)
        connection.send(msg_hash.encode())
        connection.close()

    def registration_server(self):
        # Start listening for registrations on the network
        # self._reg_listen(multicast_host, multicast_port)
        # Create a thread for the registration listener.
        reg_server = threading.Thread(target=self._reg_listen,
                                      args=(self.multicast_host,
                                            self.multicast_port))
        reg_server.start()

    def chat_server(self):
        # Start the tcp server
        chat_server = threading.Thread(target=self._chat_listen,
                                       args=(self.server_host,
                                             self.server_port))
        chat_server.start()


def chat_console(client, server):
    global current_command
    commands = []
    commands.append('- : Clear the current persistent conversation recipient if there is one.')
    commands.append('-users : List the current users.')
    commands.append('/help : Display this help')
    commands.append('/all : Send a message to all users')
    commands.append('/<user> : Send a message to <user>')
    commands.append('//all : Send a message to all users on the net and persist recipients.')
    commands.append('//<user> : Persist a conversation with <user>\n{}#:'.format(current_command))

    persistent_user = ''

    while True:
        try:
            command = input('{}#: '.format(current_command))
        except KeyboardInterrupt:
            client._register(bye=True)
            os._exit(0)
        if command[:5] == '/help':
            for command in commands:
                print(command)
        elif command[:2] == '//':  # Expect a persistent conversation
            user = command.split(' ')[0][2:]
            persistent_user = user
            msg = command[(len(user) + 3):]
            if len(msg) < 1448:
                current_command = '//{}'.format(user)
                if user == 'all':
                    for net_user in server.registrants:
                        result = client.send_message(server.registrants, net_user, msg)
                else:
                    result = client.send_message(server.registrants, user, msg)
                    if not result:
                        persistent_user = ''
            else:
                print("Your message is too long. Try again.")
        elif command[:1] == '/':  # Send a message to single user
            user = command.split(' ')[0][1:]
            msg = command[(len(user) + 2):]
            if len(msg) < 1448:
                if user == 'all':
                    for net_user in server.registrants:
                        result = client.send_message(server.registrants, net_user, msg)
                else:
                    result = client.send_message(server.registrants, user, msg)
            else:
                print("Your message is too long. Try again.")
        elif command[:6] == '-users':
            for k, v in server.registrants.items():
                print("User {}: {}".format(k, v))
        #    for user in server.registrants.items():
        #        print(user)
        elif command[:1] == '-':
            current_command = ''
            persistent_user = ''
        elif persistent_user != '':  # Expect any text to the current persistent conversation
            if len(command) < 1448:
                if persistent_user == 'all':
                    for net_user in server.registrants:
                        client.send_message(server.registrants, net_user, command)
                else:
                    client.send_message(server.registrants, persistent_user, command)
            else:
                print("Your message is too long. Try again.")
        else:
            print("Enter a valid command, or enter '/help' to learn the available commands.")


if __name__ == '__main__':
    global client, server, current_command
    current_command = ''


    parser = argparse.ArgumentParser(description='This program sends multicast messages out on to the network to' +
                                                 ' register with available users who are currently listening on TCP.' +
                                                 ' Each user listening on TCP will register the multicast message ' +
                                                 'and accept messages from the new multicast registrant provided ' +
                                                 'the client is able to decrypt messages with a symmetric key.')

    parser.add_argument("user", help="The user name you would like to register on the network.")
    parser.add_argument("--tcp", help="The TCP port you would like the chat server to listen on. (Default = 9876)",
                        default=9876, type = int)
    parser.add_argument("--reg", help="The multicast port you would like the chat server to listen on. (Default = 9999)",
                        default=9999, type = int)
    parser.add_argument("--periodic", help="Periodically re-register with the multicast network every 15 seconds. " +
                        "This is useful if you want to make yourself know to all new nodes on the network.",
                        action='store_true')

    args = parser.parse_args()

    chat_key = getpass.getpass(prompt='Encryption key: ')

    # Chosen username needs to be fed to both client and server for dupe detection
    server = ChatServer(user=args.user, multicast_port=args.reg,
                        server_port=args.tcp, key=chat_key)

    # Start the tcp chat server thread
    server.chat_server()
    time.sleep(.2)  # Race condition where TCP socket isn't bound before multicast msg is sent and returned for dupe user

    # Chosen username needs to be fed to both client and server for dupe detection
    client = ChatClient(user=args.user, multicast_port=args.reg,
                        client_port=args.tcp, key=chat_key)

    # start the multicast registration listener thread
    server.registration_server()

    # If we want to broadcast periodically:
    if args.periodic:
        periodicreg = threading.Thread(target=client.periodic_reg)
        periodicreg.start()

    # Start the chat console
    chat_console(client, server)
