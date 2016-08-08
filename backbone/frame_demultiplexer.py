#!/usr/bin/env python
import logging

import binascii
import selectors34 as selectors
import struct


logging.basicConfig(level=logging.DEBUG)

# get the best selector for the system
selector = selectors.DefaultSelector()

sockets = {}

NODE_ID_BCAST = 255

def close_socket(conn):
    logging.info("closing connection: %s" % conn)
    try:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except Exception as e:
        logging.exception(e)

    try:
        selector.unregister(conn)
    except Exception as e:
        logging.exception(e)

def accept(sock, mask, *args):
    conn, (host, port) = sock.accept()

    print('accepted', conn, 'from', (host, port))
    conn.setblocking(False)

    # TODO: use mac address from ieee80211 frame header for mapping?
    # assume last byte of ip is node_id
    node_id = int(host.split(".")[-1])
    sockets[node_id] = conn
    selector.register(conn, selectors.EVENT_READ, (read, [node_id]))

def send_all(data, exclude_node_ids=None):
    if exclude_node_ids is None:
        exclude_node_ids = []

    filtered_sockets = dict(filter(lambda (x, y): x not in exclude_node_ids, sockets.items()))

    if not filtered_sockets:
        logging.info("ignoring broadcast for topoligy with single node!")
        return

    # print "sending data to nodes: %s, len: %d" % (', '.join(map(str, filtered_sockets.keys())), len(data))
    for node_id, socket in filtered_sockets.items():

        # TODO: improve performance
        # TODO: parallel send?
        sel = selectors.DefaultSelector()
        sel.register(socket, selectors.EVENT_WRITE)
        sel.select()
        socket.sendall(data)
        sel.unregister(socket)

def read(conn, mask, from_node_id):
    try:
        # TODO: use recv_from for from_node_id!
        # conn.send(conn.recv(1024))

        BUF_SIZE = 8192
        send_all(conn.recv(BUF_SIZE), exclude_node_ids=[from_node_id])

        # # TODO: use big-endian order!
        # # '=' : no alignment
        # # 'B' : unsigned char
        # # 'I' : unsigned int
        # struct_str = "=BI"
        # struct_size = struct.calcsize(struct_str)
        #
        #
        # data = conn.recv(struct_size, socket.MSG_WAITALL)
        #
        # logging.info("read packet from %s", from_node_id)
        # # print "received: %s" % binascii.hexlify(data)
        #
        # if(len(data) != struct_size):
        #     raise ValueError("Not enough bytes returned! Expected: %d, got: %d" % (struct_size, len(data)))
        #
        # node_id, frame_len = struct.unpack(struct_str, data[:5])
        #
        #
        # actual_data = conn.recv(frame_len, socket.MSG_WAITALL)
        #
        # if (len(actual_data) != frame_len):
        #     raise ValueError("Not enough bytes returned! Expected: %d, got: %d" % (frame_len, len(actual_data)))
        #
        # if data:
        #     frame = data[1:] + actual_data
        #     send_all(frame, exclude_node_ids=[from_node_id])
        #
        # else:
        #     close_socket(conn)
    except Exception as e:
        logging.exception(e)

        close_socket(conn)


if __name__ == '__main__':

    host, port = "0.0.0.0", 1234
    backlog = 10
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    sock.setblocking(False)
    # TODO: backlog size
    sock.listen(backlog)
    selector.register(sock, selectors.EVENT_READ, (accept, []))

    print "entering main loop ..."
    try:
        while 1:
            # See Also: https://docs.python.org/3/library/selectors.html
            # This returns a list of (key, events) tuples, one for each ready file object.
            # key is the SelectorKey instance corresponding to a ready file object. events is a bitmask of events ready on this file object.

            events = selector.select()
            for key, mask in events:
                callback, args = key.data
                callback(key.fileobj, mask, *args)
    except KeyboardInterrupt:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()