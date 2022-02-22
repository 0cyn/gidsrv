#!/usr/bin/python3

from sanic import Sanic
from sanic.response import text

from multiprocessing.managers import BaseManager
from multiprocessing.connection import Listener

import json

app = Sanic("gid-srv")

def communicator(command, talkback=False):
    if talkback:
        listener = Listener(address=('', 0), authkey=b'tuktuktuk')
        return_port = listener.address[1]
        command = command + (return_port,)

    class QueueManager(BaseManager): pass
    QueueManager.register('get_queue')

    m = QueueManager(address=('', 55555), authkey=b'tuktuktuk')
    m.connect()
    queue = m.get_queue()
    queue.put(command)

    if talkback:
        conn = listener.accept()
        server_return = conn.recv()
        conn.close()
        listener.close()
        return server_return

def job_serialize(soc, type, kbag):
    return json.dumps({'soc': soc, 'job_type': type, 'kbag': kbag})

@app.get("/8930")
async def decrypt(request):
    item = job_serialize('8930', 'decrypt', request.args.get('kbag'))
    item = (item,)
    response = communicator(item, True)
    return text(response)

@app.get("/8010")
async def decrypt(request):
    item = job_serialize('8010', 'decrypt', request.args.get('kbag'))
    item = (item,)
    response = communicator(item, True)
    return text(response)

@app.get("/8000")
async def decrypt(request):
    item = job_serialize('8000', 'decrypt', request.args.get('kbag'))
    item = (item,)
    response = communicator(item, True)
    return text(response)

@app.get("/8015")
async def decrypt(request):
    item = job_serialize('8015', 'decrypt', request.args.get('kbag'))
    item = (item,)
    response = communicator(item, True)
    return text(response)

@app.get("/8004")
async def decrypt(request):
    item = job_serialize('8004', 'decrypt', request.args.get('kbag'))
    item = (item,)
    response = communicator(item, True)
    return text(response)

app.run(host='0.0.0.0', port=80, access_log=True)
