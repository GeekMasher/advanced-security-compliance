from ghascompliance.utils.config import Config


def _header(title):
    print("----- {:12} -----".format(title))


def prettyPolicy(policy):
    pass


def prettyConfig(config: Config):
    elememt = "{padding}{title} :: {value:<24}"

    _header("Configuration")
    print(elememt.format(padding="", title="Config Name", value=config.name))
