from texttable import Texttable


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
        return str(self.name, 'utf-8')

    def print_entire_chain(self):
        cert = self.head_val
        table = Texttable()
        table.set_cols_width([40, 10, 10])
        table.set_deco(table.BORDER | Texttable.HEADER)

        table.header([self.print_pretty_name(), 'Result', 'Depth'])
        while cert is not None:
            table.add_row([cert.common_name, cert.result, cert.depth])
            cert = cert.next_val
        print("\n" + table.draw() + "\n")
