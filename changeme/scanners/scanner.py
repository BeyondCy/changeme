class Scanner(object):
    def __init__(self, data, targets, config):
        """
        :param data:
        :param targets:
        :param config:
        """

        # Retrieve value from dictionary        
        if config.custom_creds:
            self.creds = config.custom_creds
        else:
            self.creds = data['auth']['credentials']
        
        self.contributor = None
        if 'contributor' in data:
            self.contributor = data['contributor']
        
        self.name = None
        if 'name' in data:
            self.name = data['name']
        
        self.type = None
        if 'type' in data['auth']:
            self.type = data['auth']['type']

        if config.port:
            self.port = config.port
        else:
            self.port = None
            if 'default_port' in data:
                self.port = data['default_port']

        if config.ssl:
            self.ssl = config.ssl
        else:
            self.ssl = None
            if 'ssl' in data:
                self.ssl = data['ssl']

        self.targets = targets
        self.config = config
        self.logger = config.logger

    def _class_name(self):
        return self.__class__.__name__
