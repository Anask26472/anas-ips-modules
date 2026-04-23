from ips.engine import IPSEngine


def main():
    engine = IPSEngine()
    print('status:', engine.get_status())
    print('stats:', engine.get_stats())
    print('health import ok')


if __name__ == '__main__':
    main()
