class CertNode:
    def __init__(self, result, depth, common_name):
        self.common_name = common_name
        self.result = result
        self.depth = depth
        self.next_val = None


class SinglyLinkedList:
    def __init__(self):
        self.head_val = None

    def at_end(self, new_cert: CertNode):
        if self.head_val is None:
            self.head_val = new_cert
            return
        last_entry = self.head_val
        while last_entry.next_val:
            last_entry = last_entry.next_val
        last_entry.next_val = new_cert

    def pretty_print(self):
        cert = self.head_val
        while cert is not None:
            if cert.depth == 0:
                print('[*]' + ('-' * 10) + ' {0}\t{1}'.format(cert.common_name, cert.result) + ('-' * 10) + '[*]')
            else:
                print('[*] {0}|{2}|\t\t{1}'.format(cert.result, cert.common_name, cert.depth))
            cert = cert.next_val
