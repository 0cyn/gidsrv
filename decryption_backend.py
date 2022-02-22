import subprocess
import os, os.path
import json
import string, random
import hashlib

from multiprocessing.managers import BaseManager
from multiprocessing import Process, Queue
from multiprocessing.connection import Client

from collections import namedtuple

from log import log

IPWNDFU_FOLDER = '/home/cynder/hd-ipwndfu/'
API_VERSION = 0


crypt_job = namedtuple('crypt_job', ['token', 'soc', 'keybag'])


class InputValidator:
    @classmethod
    def validate_gid_decrypt_kbag_io(cls, kbag: str):
        try:

            try:
                int(kbag, 16)
            except ValueError:
                return False

            try:
                assert isinstance(kbag, str)
                assert len(kbag) == 96
            except AssertionError:
                return False 

        except Exception:
            return False

        return True
    
    @classmethod 
    def validate_paranoid_shell_command_input(cls, item):

        try:
            assert isinstance(item, str)
            assert item.isalnum()

        except AssertionError:
            return False 
            
        return True


class OutputSerializer:
    @classmethod
    def generate(cls, success=False, error_str=None, response_dict=None):
        out = {}
        out['success'] = success
        if error_str:
            out['error'] = error_str
        if response_dict:
            out['response'] = response_dict
        return json.dumps(out)
    
    @classmethod
    def generate_failure(cls, reason):
        # return cynder
        return cls.generate(error_str=reason)
    
    @classmethod 
    def generate_decrypted_keybag(cls, job, output):
        response_dict = {
            'job': str(job.token.hex()),
            'target': str(job.soc),
            'input': str(job.keybag),
            'response': str(output)
        }
        return cls.generate(True, None, response_dict)



class DecryptionBackend:
    def __init__(self):
        self.queue = None
        self.ipc_mgr = None
        self.process_location = ""

        self.default_crypto_module = IPwnDFUBashCryptoModule()

    def go(self):
        while True:
            inp = self.queue.get()
            try:
                in_dict = json.loads(inp[0])

                soc = in_dict['soc']
                kbag= in_dict['kbag']
                job_type = in_dict['job_type']
            except Exception as ex:
                self.talkback("Request was improperly serialized", inp[1])

            if job_type == 'decrypt':
                self.talkback(self.decrypt(soc, kbag), inp[1])
            
            else:
                self.talkback('problem with request', inp[1])

    def startup(self):
        self.queue = Queue()
        process = Process(target=self.launch_queue_server, args=(self.queue,))
        process.start()

        self.go()
    
    def launch_queue_server(self, queue):

        class QueueManager(BaseManager): pass

        QueueManager.register('get_queue', callable=lambda:self.queue)
        m = QueueManager(address=('', 55555), authkey=b'tuktuktuk')
        s = m.get_server()
        s.serve_forever()
    
    def talkback(self, msg, port):
        conn = Client(address=('', port), authkey=b'tuktuktuk')
        conn.send(msg)
        conn.close()

    def decrypt(self, soc_target: str, keybag: str):
        try:

            job_token = hashlib.sha256()
            job_token.update(soc_target.encode('utf-8'))
            job_token.update(keybag.encode('utf-8'))
            job_token = job_token.digest()

            job = crypt_job(token=job_token, soc=soc_target, keybag=keybag)

            return self.submit(job)
        except Exception as ex:
            
            log.error(f'Exception on decode func: {ex}')
            return OutputSerializer.generate_failure("Internal Processing Error")

    def submit(self, job: crypt_job):

        try:
            assert InputValidator.validate_gid_decrypt_kbag_io(job.keybag)
            assert InputValidator.validate_paranoid_shell_command_input(job.soc)
            assert InputValidator.validate_paranoid_shell_command_input(job.keybag)

        except AssertionError as ex:
            log.warn(f"Validation Failed: {job}")
            return OutputSerializer.generate_failure("Process Input Validation Failed.")

        output_str = self.default_crypto_module.do_gid_decrypt(job)
        
        try:
            assert InputValidator.validate_gid_decrypt_kbag_io(output_str)

        except AssertionError:
            log.error(f'Bad Process Output: {output_str}')
            return OutputSerializer.generate_failure("Internal Processing Error")

        return OutputSerializer.generate_decrypted_keybag(job, output_str)

    
class CryptoModule:
    def __init__(self):
        pass 
    
    def do_gid_decrypt(self, job):
        pass 

    def do_gid_encrypt(self, job):
        pass 
    
    def do_uid_encrypt(self, job):
        pass 

    def do_uid_decrypt(self, job):
        pass 
    
    def do_sep_decrypt(self, job): 
        pass 
    
    def do_sep_encrypt(self, job):
        pass 


class IPwnDFUBashCryptoModule(CryptoModule):
    def __init__(self):
        self.process_location = None 
        self.ipwndfu_application_verify()

    def ipwndfu_application_verify(self):
        process_location = IPWNDFU_FOLDER + 'ipwndfu'

        if not os.path.exists(process_location):
            raise AssertionError("ipwndfu bin not in specified folder")

        process_help_output = subprocess.getoutput(process_location)

        is_ipwndfu = 'USAGE: ipwndfu [options]' in process_help_output

        is_hd_ipwndfu = 'List devices' in process_help_output

        if not is_ipwndfu:
            raise AssertionError("Process is not ipwndfu")

        if not is_hd_ipwndfu:
            raise AssertionError("Requires ipwndfu implementation https://github.com/hack-different/ipwndfu")

        self.process_location = process_location

    def do_gid_decrypt(self, job):
        
        assert self.process_location != ""
        
        decrypt_process_launch_string = "{} --dev={} --decrypt-gid={} | tail -n1"
        decrypt_process_launch_string = decrypt_process_launch_string.format(self.process_location, job.soc, job.keybag)
        
        try:
            output_str = subprocess.getoutput(decrypt_process_launch_string)
            output_str = output_str.strip()
        except Exception as ex:
            log.error(f'Process launch failed! {ex}')
            return "process launch failure"

        return output_str

    def do_gid_encrypt(self, job):
        pass 
    
    def do_uid_encrypt(self, job):
        pass 

    def do_uid_decrypt(self, job):
        pass 
    
    def do_sep_decrypt(self, job): 
        pass 
    
    def do_sep_encrypt(self, job):
        pass

# this bit nicely divvys up a standard DFU usb serial string into a usable 'object' representing its fields

_serial_number = namedtuple('serial', ['cpid', 'cprv', 'cpfm', 'scep', 'bdid', 'ecid', 'ibfl', 'srtg', 'pwned'])

def get_serial(_serial):
    tokens = _serial.split(' ')
    cpid = ''
    cprv = ''
    cpfm = ''
    scep = ''
    bdid = ''
    ecid = ''
    ibfl = ''
    srtg = ''
    pwned = False
    for t in tokens:
        v = t.split(':')[-1]
        if 'CPID:' in t:
            cpid = v
        elif 'CPRV' in t:
            cprv = v
        elif 'CPFM' in t:
            cpfm = v
        elif 'SCEP' in t:
            scep = v
        elif 'BDID' in t:
            bdid = v
        elif 'ECID' in t:
            ecid = v
        elif 'IBFL' in t:
            ibfl = v
        elif 'SRTG' in t:
            srtg = v
        elif 'PWND' in t:
            pwned = True
    return _serial_number(cpid, cprv, cpfm, scep, bdid, ecid, ibfl, srtg, pwned)

backend = DecryptionBackend()
backend.startup()
