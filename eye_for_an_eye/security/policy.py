import ipaddress


def allow_response(config, command, source_ip, transport):
    if transport != 'tcp' or not config.deception.enabled:
        return False
    if command == 'garbage':
        return config.lab.enabled and ipaddress.ip_address(source_ip).is_loopback
    return command == 'services'
