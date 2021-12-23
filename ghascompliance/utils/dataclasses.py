def _dataclass_from_dict(klass, dikt):
    try:
        fieldtypes = klass.__annotations__
        return klass(**{f: _dataclass_from_dict(fieldtypes[f], dikt[f]) for f in dikt})

    except KeyError as err:
        raise Exception(f"Unknown key being set in configuration file : {err}")

    except AttributeError as err:
        if isinstance(dikt, (tuple, list)):
            return [_dataclass_from_dict(klass.__args__[0], f) for f in dikt]
        return dikt
