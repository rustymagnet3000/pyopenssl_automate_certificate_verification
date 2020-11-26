class CertNode:
    def __init__(self, result, depth, common_name):
        self.common_name = common_name
        self.result = result
        self.depth = depth
        self.next_val = None


class SinglyLinkedList:
    def __init__(self, name):
        self.head_val = None
        self.name = name

    def at_end(self, new_cert: CertNode):
        if self.head_val is None:
            self.head_val = new_cert
            return
        last_entry = self.head_val
        while last_entry.next_val:
            last_entry = last_entry.next_val
        last_entry.next_val = new_cert

    def print_pretty_name(self):
        print('\n' + ('*' * 10) + ' ' + str(self.name, 'utf-8') + ' ' + ('*' * 10))

    def print_entire_chain(self):
        cert = self.head_val
        while cert is not None:
            print('[*] {0}\t|\t{2}\t|\t\t{1}'.format(cert.result, cert.common_name, cert.depth))
            cert = cert.next_val
