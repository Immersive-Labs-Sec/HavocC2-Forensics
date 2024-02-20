# Copyright (C) 2024 Kev Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/HavocC2-Forensics
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import argparse
import struct
import binascii
from binascii import unhexlify

from uuid import uuid4


try:
    import pyshark
except ImportError:
    print("[-] Pyshark not installed, please install with 'pip install pyshark'")
    exit(0)

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    print("[-] PyCryptodome not installed, please install with 'pip install pycryptodome'")
    exit(0)



demon_constants = {
    1: "GET_JOB",
    10: 'COMMAND_NOJOB',
    11: 'SLEEP',
    12: 'COMMAND_PROC_LIST',
    15: 'COMMAND_FS',
    20: 'COMMAND_INLINEEXECUTE',
    21: 'COMMAND_JOB',
    22: 'COMMAND_INJECT_DLL',
    24: 'COMMAND_INJECT_SHELLCODE',
    26: 'COMMAND_SPAWNDLL',
    27: 'COMMAND_PROC_PPIDSPOOF',
    40: 'COMMAND_TOKEN',
    99: 'DEMON_INIT',
    100: 'COMMAND_CHECKIN',
    2100: 'COMMAND_NET',
    2500: 'COMMAND_CONFIG',
    2510: 'COMMAND_SCREENSHOT',
    2520: 'COMMAND_PIVOT',
    2530: 'COMMAND_TRANSFER',
    2540: 'COMMAND_SOCKET',
    2550: 'COMMAND_KERBEROS',
    2560: 'COMMAND_MEM_FILE', # Beacon Object File
    4112: 'COMMAND_PROC', # Shell Command
    4113: 'COMMMAND_PS_IMPORT',
    8193: 'COMMAND_ASSEMBLY_INLINE_EXECUTE',
    8195: 'COMMAND_ASSEMBLY_LIST_VERSIONS',
}


# Used to store the AES Keys for each session
sessions = {}


def tsharkbody_to_bytes(hex_string):
    """
    Converts a TShark hex formated string to a byte string.
    
    :param hex_string: The hex string from TShark.
    :return: The byte string.
    """
    # its concatonated strings
    hex_string = hex_string.replace(':', '')
    #unhex it
    hex_bytes = unhexlify(hex_string)
    return hex_bytes



def aes_decrypt_ctr(aes_key, aes_iv, encrypted_payload):
    """
    Decrypts an AES-encrypted payload in CTR mode.

    :param aes_key: The AES key as a byte string.
    :param aes_iv: The AES IV (Initialization Vector) for the counter, as a byte string.
    :param encrypted_payload: The encrypted payload as a byte string.
    :return: The decrypted plaintext as a byte string.
    """
    # Initialize the counter for CTR mode
    ctr = Counter.new(128, initial_value=int.from_bytes(aes_iv, byteorder='big'))

    # Create the cipher in CTR mode
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

    # Decrypt the payload
    decrypted_payload = cipher.decrypt(encrypted_payload)

    return decrypted_payload



def parse_header(header_bytes):
    """
    Parses a 20-byte header into an object.

    :param header_bytes: A 20-byte header.
    :return: A dictionary representing the parsed header.
    """
    if len(header_bytes) != 20:
        raise ValueError("Header must be exactly 20 bytes long")

    # Unpack the header
    payload_size, magic_bytes, agent_id, command_id, mem_id = struct.unpack('>I4s4sI4s', header_bytes)

    # Convert bytes to appropriate representations
    magic_bytes_str = binascii.hexlify(magic_bytes).decode('ascii')
    agent_id_str = binascii.hexlify(agent_id).decode('ascii')
    mem_id_str = binascii.hexlify(mem_id).decode('ascii')
    command_name = demon_constants.get(command_id, f'Unknown Command ID: {command_id}')

    return {
        'payload_size': payload_size,
        'magic_bytes': magic_bytes_str,
        'agent_id': agent_id_str,
        'command_id': command_name,
        'mem_id': mem_id_str
    }


def parse_request(http_pair, magic_bytes, save_path):
    request = http_pair['request']
    response = http_pair['response']#

    unique_id = uuid4()

    print("[+] Parsing Request")


    try:
        request_body = tsharkbody_to_bytes(request.get('file_data', ''))
        header_bytes = request_body[:20]
        request_payload = request_body[20:]
        request_header = parse_header(header_bytes)
    except Exception as e:
        print(f"[!] Error parsing request body: {e}")
        return


    # If there is no magic this is not Havoc
    if request_header.get("magic_bytes", '') != magic_bytes:
        return


    if request_header['command_id'] == 'DEMON_INITIALIZE':
        print("[+] Found Havoc C2")
        print(f"  [-] Agent ID: {request_header['agent_id']}")
        print(f"  [-] Magic Bytes: {request_header['magic_bytes']}")
        print(f"  [-] C2 Address: {request.get('uri')}")

        aes_key = request_body[20:52]
        aes_iv = request_body[52:68]

        print(f"  [+] Found AES Key")
        print(f"    [-] Key: {binascii.hexlify(aes_key).decode('ascii')}")
        print(f"    [-] IV: {binascii.hexlify(aes_iv).decode('ascii')}")

        if request_header['agent_id'] not in sessions:
            sessions[request_header['agent_id']] = {
                "aes_key": aes_key,
                "aes_iv": aes_iv
            }
        
        # We dont want to process the rest of the request
        response_payload = None

    elif request_header['command_id'] == 'GET_JOB':
        print("  [+] Job Request from Server to Agent")
         # if the pcap did not contain an init or we have manually passed keys add the found keys message
        
        # Grab the response header to get the incoming request. 

        try:
            response_body = tsharkbody_to_bytes(response.get('file_data', ''))

        except Exception as e:
            print(f"[!] Error parsing request body: {e}")
            return


        if 'fd6254185e00' in hexlify(response_body).decode('ascii'):
            print(hexlify(response_body).decode('ascii'))


        header_bytes = response_body[:12]
        response_payload = response_body[12:]
        command_id = struct.unpack('<H', header_bytes[:2])[0]

        command = demon_constants.get(command_id, f'Unknown Command ID: {command_id}')

        print(f"    [-] C2 Address: {request.get('uri')}")
        print(f"    [-] Comamnd: {command}")

    else:
        print(f"  [+] Unknown Command: {request_header['command_id']}")
        response_payload = None

    # If we have keys lets decode the payload
    if save_path:

        # Create the output path if it doesn't exist
        if save_path and not os.path.exists(save_path):
            print(f"[!] Save path {save_path} does not exist, creating")
            os.makedirs(save_path)

        aes_keys = sessions.get(request_header['agent_id'], None)

        if not aes_keys:
            print(f"[!] No AES Keys for Agent with ID {request_header['agent_id']}")
            return
        
        # Decrypt the Request Body
        
        if request_payload:
            print("  [+] Decrypting Request Body")
            decrypted_request = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], request_payload)

            save_file = f'{save_path}/{unique_id}-request-{request_header["agent_id"]}.bin'
            with open(save_file, 'wb') as output_file:
                output_file.write(decrypted_request)


        # Dcrypt the Response Body
        if response_payload:
            print("  [+] Decrypting Response Body")
            decrytped_response = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], response_payload)

            save_file = f'{save_path}/{unique_id}-response-{request_header["agent_id"]}.bin'
            with open(save_file, 'wb') as output_file:
                output_file.write(decrytped_response)


def read_pcap_and_get_http_pairs(pcap_file, magic_bytes, save_path):
    capture = pyshark.FileCapture(pcap_file, display_filter='http')
    http_pairs = {}
    current_stream = None
    request_data = None

    print("[+] Parsing Packets")

    for packet in capture:
        try:
            # Check if we are still in the same TCP stream
            if current_stream != packet.tcp.stream:
                # Reset for a new stream
                current_stream = packet.tcp.stream
                request_data = None

            if 'HTTP' in packet:
                if hasattr(packet.http, 'request_method'):
                    # This is a request
                    request_data = {
                        'method': packet.http.request_method,
                        'uri': packet.http.request_full_uri,
                        'headers': packet.http.get_field_value('request_line'),
                        'file_data': packet.http.file_data if hasattr(packet.http, 'file_data') else None
                    }
                elif hasattr(packet.http, 'response_code') and request_data:
                    # This is a response paired with the previous request
                    response_data = {
                        'code': packet.http.response_code,
                        'phrase': packet.http.response_phrase,
                        'headers': packet.http.get_field_value('response_line'),
                        'file_data': packet.http.file_data if hasattr(packet.http, 'file_data') else None
                    }
                    # Pair them together in a dictionary
                    http_pairs[f"{current_stream}_{packet.http.request_in}"] = {
                        'request': request_data,
                        'response': response_data
                    }

                    parse_request(http_pairs[f"{current_stream}_{packet.http.request_in}"], magic_bytes, save_path)

                    #print(http_pairs[f"{current_stream}_{packet.http.request_in}"])

                    request_data = None  # Reset request data after pairing
        except AttributeError as e:
            # Ignore packets that don't have the necessary HTTP fields
            pass



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Havoc Traffic from a PCAP')

    parser.add_argument(
        '--pcap',
        help='Path to pcap file',
        required=True)
    

    parser.add_argument(
        "--aes-key", 
        help="AES key", 
        required=False)
    
    parser.add_argument(
        "--aes-iv", 
        help="AES initialization vector", 
        required=False)
    
    parser.add_argument(
        "--agent-id", 
        help="Agent ID", 
        required=False)

    parser.add_argument(
        '--save',
        help='Save decrypted payloads to file',
        default=False,
        required=False)

    parser.add_argument(
        '--magic',
        help='Set the magic bytes marker for the Havoc C2 traffic',
        default='deadbeef',
        required=False)


    # Parse the arguments
    args = parser.parse_args()

    # Custom check for the optional values
    if any([args.aes_key, args.aes_iv, args.agent_id]) and not all([args.aes_key, args.aes_iv, args.agent_id]):
        parser.error("[!] If you provide one of 'aes-key', 'aes-iv', or 'agent-id', you must provide all three.")
    
    if args.agent_id and args.aes_key and args.aes_iv:
        sessions[args.agent_id] = {
            "aes_key": unhexlify(args.aes_key),
            "aes_iv": unhexlify(args.aes_iv)
        }
        print(f"[+] Added session keys for Agent ID {args.agent_id}")

    #find_havoc_packets(packets, args.save)


    # Usage example
    http_pairs = read_pcap_and_get_http_pairs(args.pcap, args.magic, args.save)

