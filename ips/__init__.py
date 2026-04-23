__all__ = ['IPSEngine', 'create_app']


def __getattr__(name):
    if name == 'IPSEngine':
        from .engine import IPSEngine
        return IPSEngine
    if name == 'create_app':
        from .api.bridge import create_app
        return create_app
    raise AttributeError(name)
