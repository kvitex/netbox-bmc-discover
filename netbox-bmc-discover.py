#!/usr/bin/env python3
from ipaddress import ip_interface
from flask import Flask
import pynetbox
import yaml
import time


app = Flask(__name__)
@app.route('/metrics')
def metrics_output():
    # startTime = time.time()
    config_file_name = 'config.yml'
    try:
        with open(config_file_name) as config_file:
            cfg = yaml.load(config_file.read())
    except FileNotFoundError or FileExistsError as Error:
        print('Can not open configuration file {}'.format(config_file_name))
        print(Error)
        exit(-1)
    except yaml.scanner.ScannerError as Error:
        print('Error while parsing configuration file {}'.format(config_file_name))
        print(Error)
        exit(-1)
    except Exception as Error:
        print(Error)
        exit(-1)
    except yaml.scanner.ScannerError as Error:
        print('Error while parsing devices file {}'.format(config_file_name))
        print(Error)
        exit(-1)
    except Exception as Error:
        print(Error)
        exit(-1)
    try:
        nb = pynetbox.api(**cfg['netbox'])
    except KeyError as Error:
        print('Netbox configuration not found.')
        exit(-1)
    except Exception as Error:
        print('PyNetbox: ', Error)
        exit(-1) 
    sd_list = []
    nb_ip_addresses = dict(map(lambda x: (x.interface.id, str(ip_interface(x).ip)), nb.ipam.ip_addresses.all()))
    startTime = time.time()
    for bmc_interface in nb.dcim.interfaces.filter(mgmt_only=True):
        bmc_interface_ip = nb_ip_addresses.get(bmc_interface.id, None)
        device_vendor = None
        for vendor in cfg['vendors']:
            if vendor['netbox'] == str(bmc_interface.device.device_type.manufacturer):
                device_vendor = vendor['id']
        secret = None
        for nb_secret in nb.secrets.secrets.filter(device_id=bmc_interface.device.id):
            if str(nb_secret.role) in cfg['secret_roles']:
                secret = nb_secret.plaintext
        if (bmc_interface_ip is not None) and (device_vendor is not None) and (secret is not None) and (str(bmc_interface.device.status) == 'Active'):
            sd_list.append(
                {
                    'labels': {
                        'hostname': str(bmc_interface.device),
                        'device_role': str(bmc_interface.device.device_role),
                        'site': str(bmc_interface.device.site),
                        'type': device_vendor,
                        'secret': secret,
                        'ip': bmc_interface_ip
                    },
                    'targets': [bmc_interface_ip, ]
                    
                }
            )
    with open(cfg['output_file'], 'w+') as output_file:
        print(yaml.dump(sd_list, output_file, default_flow_style=False))
    metrics = [
        '#',
        'netbox_bmc_discover_up 1',
        'netbox_bmc_discover_duration {}'.format(time.time() - startTime),
        '#'
    ]
    return '\n'.join(metrics)
    
            



            