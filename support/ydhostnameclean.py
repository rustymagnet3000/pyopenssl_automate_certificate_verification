import re


class YDHostNameCleaner:
    def __init__(self, hostnames_file):
        self.hostnames = []
        self.file = hostnames_file.read().split("\n")

    def __enter__(self):
        """
            Check if each line is a valid Hostname
            if line fails, return don't return that line
            :return: [hostnames list]
        """
        for line in self.file:
            if len(line) > 0 and line[0] != '#':
                host_sanitize_l1 = YDHostNameCleaner.remove_wildcard(line)
                host_sanitize_l2 = YDHostNameCleaner.is_valid_hostname(host_sanitize_l1)
                if host_sanitize_l2 is not None:
                    self.hostnames.append(host_sanitize_l2)
        print("[*]Cleaned hostnames\t{}".format(self.hostnames))
        return self.hostnames

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("[*]clean-up. Closing hostname file.")

    @staticmethod
    def remove_wildcard(hostname):
        if hostname[0:2] == "*.":
            hostname = hostname[2:]
            hostname = YDHostNameCleaner.remove_wildcard(hostname)
        return hostname

    @staticmethod
    def is_valid_hostname(hostname):
        hostname_regex = re.compile("(?!-)[A-Z\d-]{5,63}(?<!-)$", re.IGNORECASE)
        num_periods = re.findall(r'\.', hostname)
        if len(hostname) > 255:
            return None
        if len(num_periods) == 0 or len(num_periods) > 7:   # remove hostnames with no periods or too many periods
            return None
        if len(re.findall(r'\s+', hostname)) > 0:           # remove hostnames with whitespace ( spaces / tabs )
            return None
        if all(hostname_regex.match(x) for x in hostname.split(".")) is not True:
            return hostname
        return None
